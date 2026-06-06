import { useEffect } from 'react'
import { FolderOpen } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import ProjectCard from './ProjectCard'
import { Card } from '@/components/ui/card'

interface ProjectListProps {
  onCreateClick: () => void
}

export default function ProjectList({ onCreateClick }: ProjectListProps) {
  const { projects, loading, error, fetchProjects, removeProject } = useProjectStore()

  useEffect(() => {
    fetchProjects()
  }, [fetchProjects])

  const handleDelete = (id: string) => {
    if (window.confirm('Delete this project and all its data?')) {
      removeProject(id)
    }
  }

  if (error === 'host not allowed' && projects.length === 0) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-5 text-sm space-y-2">
        <p className="font-semibold text-destructive">Backend rejected this hostname</p>
        <p className="text-muted-foreground">
          The backend only accepts requests from hosts listed in its allowlist. To fix this:
        </p>
        <ol className="list-decimal list-inside space-y-1 text-muted-foreground">
          <li>
            Open <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">.env</code> and
            add this hostname to{' '}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">EXTRA_ALLOWED_HOSTS</code>
            {' '}(comma-separated).
          </li>
          <li>Delete the backend container: <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">docker compose rm -sf backend</code></li>
          <li>Re-create it: <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">docker compose up -d backend</code></li>
        </ol>
      </div>
    )
  }

  if (loading && projects.length === 0) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="h-36 animate-pulse bg-muted/50" />
        ))}
      </div>
    )
  }

  if (projects.length === 0) {
    return (
      <div className="flex flex-col items-center gap-4 py-20">
        <FolderOpen className="h-12 w-12 text-muted-foreground" />
        <div className="text-center">
          <p className="font-medium">No projects yet</p>
          <p className="text-sm text-muted-foreground">
            Create a project to start analyzing firmware.
          </p>
        </div>
        <button
          className="text-sm font-medium text-primary underline-offset-4 hover:underline"
          onClick={onCreateClick}
        >
          Create your first project
        </button>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {projects.map((p) => (
        <ProjectCard key={p.id} project={p} onDelete={handleDelete} />
      ))}
    </div>
  )
}
