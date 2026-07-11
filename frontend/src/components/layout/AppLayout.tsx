import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import { useProjectStore } from '@/stores/projectStore'

export default function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const { pathname } = useLocation()
  // :projectId lives on the child route, so it isn't visible via useParams in
  // the layout — derive it from the path instead.
  const projectId = pathname.match(/^\/projects\/([^/]+)/)?.[1] ?? null
  const currentProject = useProjectStore((s) => s.currentProject)
  const fetchProject = useProjectStore((s) => s.fetchProject)

  // Ensure the project (and its active-firmware selection) is loaded on every
  // project sub-page, so the firmware picker and tabs work on direct links.
  useEffect(() => {
    if (projectId && projectId !== currentProject?.id) {
      fetchProject(projectId)
    }
  }, [projectId, currentProject?.id, fetchProject])

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <Sidebar collapsed={!sidebarOpen} onToggle={() => setSidebarOpen((v) => !v)} />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header projectId={projectId} />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
