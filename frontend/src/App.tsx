import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from '@/components/layout/AppLayout'
import ErrorBoundary from '@/components/ErrorBoundary'
import DisclaimerDialog from '@/components/DisclaimerDialog'
import PageLoader from '@/components/PageLoader'
import Toaster from '@/components/Toaster'
import ProjectRouteGuard from '@/components/ProjectRouteGuard'

// Route-level code splitting. Each page becomes its own chunk, so heavy deps
// (Monaco in ExplorePage, xterm in EmulationPage, ReactFlow in ComponentMap /
// HardwareFirmwarePage) no longer ship in the initial bundle.
const ProjectsPage = lazy(() => import('@/pages/ProjectsPage'))
const ProjectDetailPage = lazy(() => import('@/pages/ProjectDetailPage'))
const ExplorePage = lazy(() => import('@/pages/ExplorePage'))
const FindingsPage = lazy(() => import('@/pages/FindingsPage'))
const ComponentMapPage = lazy(() => import('@/pages/ComponentMapPage'))
const SbomPage = lazy(() => import('@/pages/SbomPage'))
const HardwareFirmwarePage = lazy(() => import('@/pages/HardwareFirmwarePage'))
const EmulationPage = lazy(() => import('@/pages/EmulationPage'))
const FuzzingPage = lazy(() => import('@/pages/FuzzingPage'))
const ComparisonPage = lazy(() => import('@/pages/ComparisonPage'))
const SecurityScanPage = lazy(() => import('@/pages/SecurityScanPage'))
const SecurityToolsPage = lazy(() => import('@/pages/SecurityToolsPage'))
const DeviceAcquisitionPage = lazy(() => import('@/pages/DeviceAcquisitionPage'))
const WindowsHubPage = lazy(() => import('@/pages/WindowsHubPage'))
const PeHardeningPage = lazy(() => import('@/pages/PeHardeningPage'))
const AuthenticodeDetailPage = lazy(() => import('@/pages/AuthenticodeDetailPage'))
const RegistryHivePage = lazy(() => import('@/pages/RegistryHivePage'))
const RegistryDiffPage = lazy(() => import('@/pages/RegistryDiffPage'))
const DriverMatrixPage = lazy(() => import('@/pages/DriverMatrixPage'))
const DriverDetailPage = lazy(() => import('@/pages/DriverDetailPage'))
const HelpPage = lazy(() => import('@/pages/HelpPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))

export default function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
      <DisclaimerDialog />
      <Toaster />
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Navigate to="/projects" replace />} />
          <Route element={<AppLayout />}>
            <Route path="/projects" element={<ProjectsPage />} />
            {/*
              Every /projects/:projectId/* route is wrapped in
              ProjectRouteGuard so a URL-only switch (e.g.
              /projects/A/explore → /projects/B/explore, same component
              tree, just new params) tears down stale store state that
              would otherwise render into the new project.
            */}
            <Route path="/projects/:projectId" element={<ProjectRouteGuard><ProjectDetailPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/explore" element={<ProjectRouteGuard><ExplorePage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/security" element={<ProjectRouteGuard><SecurityScanPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/findings" element={<ProjectRouteGuard><FindingsPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/map" element={<ProjectRouteGuard><ComponentMapPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/sbom" element={<ProjectRouteGuard><SbomPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/hardware-firmware" element={<ProjectRouteGuard><HardwareFirmwarePage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/emulation" element={<ProjectRouteGuard><EmulationPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/fuzzing" element={<ProjectRouteGuard><FuzzingPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/compare" element={<ProjectRouteGuard><ComparisonPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/tools" element={<ProjectRouteGuard><SecurityToolsPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/device" element={<ProjectRouteGuard><DeviceAcquisitionPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows" element={<ProjectRouteGuard><WindowsHubPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/pe-hardening" element={<ProjectRouteGuard><PeHardeningPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/pe-hardening/:signatureId" element={<ProjectRouteGuard><AuthenticodeDetailPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/registry" element={<ProjectRouteGuard><RegistryHivePage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/registry/diff" element={<ProjectRouteGuard><RegistryDiffPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/drivers" element={<ProjectRouteGuard><DriverMatrixPage /></ProjectRouteGuard>} />
            <Route path="/projects/:projectId/windows/drivers/:driverId" element={<ProjectRouteGuard><DriverDetailPage /></ProjectRouteGuard>} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
      </ErrorBoundary>
    </BrowserRouter>
  )
}
