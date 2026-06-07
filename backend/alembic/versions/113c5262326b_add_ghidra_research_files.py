"""add_ghidra_research_files

Revision ID: 113c5262326b
Revises: feab18c9d201
Create Date: 2026-06-07 00:00:00.000000

New table ``ghidra_research_files`` backing the Ghidra Research feature.
Stores .gzf Ghidra archive exports and .py/.java analysis scripts uploaded
by operators or saved by the AI via MCP. The ``import_status`` column tracks
a Rule #33 .a 202+polling state machine for the Ghidra headless import job.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "113c5262326b"
down_revision = "feab18c9d201"
branch_labels = None
depends_on = None

FILE_CATEGORY_VALUES = ("ghidra_archive", "python_script", "java_script")
IMPORT_STATUS_VALUES = ("idle", "queued", "running", "completed", "failed")


def upgrade() -> None:
    op.create_table(
        "ghidra_research_files",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("file_category", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("storage_path", sa.String(512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "import_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
        sa.Column(
            "import_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("import_error", sa.Text(), nullable=True),
    )

    op.create_index(
        "ix_ghidra_research_files_project_id",
        "ghidra_research_files",
        ["project_id"],
    )
    op.create_index(
        "ix_ghidra_research_files_sha256",
        "ghidra_research_files",
        ["sha256"],
    )

    file_category_quoted = ", ".join(f"'{v}'" for v in FILE_CATEGORY_VALUES)
    op.create_check_constraint(
        "ck_ghidra_research_files_file_category",
        "ghidra_research_files",
        f"file_category IN ({file_category_quoted})",
    )

    import_status_quoted = ", ".join(f"'{v}'" for v in IMPORT_STATUS_VALUES)
    op.create_check_constraint(
        "ck_ghidra_research_files_import_status",
        "ghidra_research_files",
        f"import_status IN ({import_status_quoted})",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_ghidra_research_files_import_status", "ghidra_research_files", type_="check"
    )
    op.drop_constraint(
        "ck_ghidra_research_files_file_category", "ghidra_research_files", type_="check"
    )
    op.drop_index("ix_ghidra_research_files_sha256", "ghidra_research_files")
    op.drop_index("ix_ghidra_research_files_project_id", "ghidra_research_files")
    op.drop_table("ghidra_research_files")
