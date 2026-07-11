# Frontend module — CloudFront serving the SPA from S3 (private, via OAC) with
# /api/* and websockets routed to the backend ALB. Reproduces the nginx reverse
# proxy from frontend/nginx.conf.template (static + /api/ proxy) at the edge.

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.name}-spa"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Baseline security response headers for the SPA: HSTS + clickjacking/MIME
# hardening. A strict Content-Security-Policy is intentionally omitted (the SPA
# uses Monaco/blob web workers + Cognito redirects, which need a carefully tuned
# policy) — see the security review follow-ups.
resource "aws_cloudfront_response_headers_policy" "security" {
  name = "${var.name}-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

locals {
  s3_origin_id  = "spa-s3"
  alb_origin_id = "backend-alb"
}

# SPA client-side routing, scoped to the S3 behavior only.
#
# This REPLACES a distribution-wide `custom_error_response` (403/404 →
# /index.html). That rewrite was global and also caught the ALB/MCP origin: an
# unknown/stale Mcp-Session-Id returns 404 from the backend, which CloudFront
# masked as `200 text/html` (index.html). The Streamable-HTTP client then can't
# tell "session expired → re-initialize" from a hard error and wedges on
# "Unexpected content type: text/html" after every backend roll. See
# enterprise/docs/MCP-FIELD-FINDINGS.md (Cloud #1).
#
# Instead, rewrite deep links to /index.html *before* they hit S3, attached only
# to the default (S3) behavior. /api/* and /mcp* have their own behaviors and
# never see this function, so their 404s pass through honestly. A genuinely
# missing asset (path with an extension) now returns a real 404 instead of
# index.html. Caveat: SPA routes containing a "." in the last path segment are
# treated as assets — keep client routes extension-less.
resource "aws_cloudfront_function" "spa_router" {
  name    = "${var.name}-spa-router"
  runtime = "cloudfront-js-2.0"
  comment = "SPA deep-link routing: rewrite extension-less paths to /index.html"
  publish = true
  code    = <<-JS
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      var last = uri.substring(uri.lastIndexOf('/') + 1);
      // No file extension in the final segment → SPA route → serve the shell.
      if (last.indexOf('.') === -1) {
        request.uri = '/index.html';
      }
      return request;
    }
  JS
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.name} Wairz SPA + API"
  price_class         = var.price_class
  aliases             = var.aliases

  origin {
    origin_id                = local.s3_origin_id
    domain_name              = var.spa_bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  origin {
    origin_id   = local.alb_origin_id
    domain_name = var.alb_dns_name
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only" # ALB listener is HTTP; TLS terminates at CloudFront
      origin_ssl_protocols   = ["TLSv1.2"]
      # MCP tool calls (and some API ops) can run tens of seconds; give the
      # origin the max default read timeout so they aren't cut to a 504 at the
      # edge. >60s needs a CloudFront service-quota increase.
      origin_read_timeout      = 60
      origin_keepalive_timeout = 60
    }
  }

  # SPA static assets (default).
  default_cache_behavior {
    target_origin_id           = local.s3_origin_id
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_router.arn
    }
  }

  # API + websockets → ALB, uncached, forward everything.
  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = local.alb_origin_id
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
    compress                 = true
  }

  # Remote MCP (Phase 5) → ALB, uncached, all methods. compress=false so the
  # Streamable HTTP SSE responses pass through unbuffered.
  dynamic "ordered_cache_behavior" {
    for_each = var.mcp_enabled ? [1] : []
    content {
      path_pattern             = "/mcp*"
      target_origin_id         = local.alb_origin_id
      viewer_protocol_policy   = "redirect-to-https"
      allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods           = ["GET", "HEAD"]
      cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
      origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
      compress                 = false
    }
  }

  # SPA client-side routing is handled by aws_cloudfront_function.spa_router on
  # the default (S3) behavior — NOT a distribution-wide custom_error_response,
  # which would also mask /mcp* and /api/* 404s as 200/index.html and break MCP
  # session recovery. See the function's comment above.

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.acm_certificate_arn == ""
    acm_certificate_arn            = var.acm_certificate_arn == "" ? null : var.acm_certificate_arn
    ssl_support_method             = var.acm_certificate_arn == "" ? null : "sni-only"
    minimum_protocol_version       = var.acm_certificate_arn == "" ? "TLSv1" : "TLSv1.2_2021"
  }
}

# Let CloudFront (via OAC) read the private SPA bucket.
data "aws_iam_policy_document" "spa_bucket" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${var.spa_bucket_arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket = var.spa_bucket
  policy = data.aws_iam_policy_document.spa_bucket.json
}
