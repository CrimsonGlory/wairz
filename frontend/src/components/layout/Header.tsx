import { useLocation } from 'react-router-dom'
import FirmwareVersionPicker from './FirmwareVersionPicker'

const pageTitles: Record<string, string> = {
  '/projects': 'Projects',
}

interface HeaderProps {
  projectId: string | null
}

export default function Header({ projectId }: HeaderProps) {
  const { pathname } = useLocation()

  const title =
    pageTitles[pathname] ??
    (pathname.includes('/explore')
      ? 'File Explorer'
      : pathname.includes('/map')
        ? 'Component Map'
        : 'Project')

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border px-6">
      <h1 className="text-lg font-semibold">{title}</h1>
      {projectId && <FirmwareVersionPicker projectId={projectId} />}
    </header>
  )
}
