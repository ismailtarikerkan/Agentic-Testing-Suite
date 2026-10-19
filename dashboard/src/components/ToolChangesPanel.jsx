import { useState, useEffect, useCallback } from 'react'
import { fetchToolChanges } from '../api'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-900 text-red-300 border border-red-700',
  HIGH:     'bg-orange-900 text-orange-300 border border-orange-700',
  MEDIUM:   'bg-yellow-900 text-yellow-300 border border-yellow-700',
  LOW:      'bg-blue-900 text-blue-300 border border-blue-800',
}

const CHANGE_TYPE_LABELS = {
  new_tool: 'New tool',
  removed_tool: 'Removed tool',
  modified: 'Modified',
}

function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] ?? 'bg-gray-800 text-gray-400 border border-gray-700'
  return <span className={`text-xs px-2 py-0.5 rounded font-semibold ${style}`}>{severity}</span>
}

function ChangeRow({ change }) {
  const [expanded, setExpanded] = useState(false)
  const hasFields = change.fields?.length > 0

  return (
    <div className="border-b border-gray-800 px-4 py-3">
      <div
        className={`flex items-center gap-3 ${hasFields ? 'cursor-pointer' : ''}`}
        onClick={() => hasFields && setExpanded((e) => !e)}
      >
        {hasFields && (
          <svg
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
            className={`w-3.5 h-3.5 text-gray-600 flex-shrink-0 transition-transform ${expanded ? 'rotate-90' : ''}`}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
          </svg>
        )}
        <span className="text-xs text-gray-600 mono flex-shrink-0 w-40">
          {new Date(change.detected_at).toLocaleString()}
        </span>
        <span className="text-sm text-gray-500 flex-shrink-0 w-24">{change.backend_name}</span>
        <span className="mono text-sm text-gray-200 flex-shrink-0 w-48 truncate">{change.tool_name}</span>
        <span className="text-xs text-gray-400 flex-shrink-0 w-24">
          {CHANGE_TYPE_LABELS[change.change_type] ?? change.change_type}
        </span>
        <SeverityBadge severity={change.severity} />
      </div>

      {expanded && hasFields && (
        <div className="mt-2 ml-6 space-y-1">
          {change.fields.map((f, i) => (
            <div key={i} className="text-xs flex gap-2 items-baseline">
              <span className="text-gray-500 w-32 flex-shrink-0 mono">{f.field}</span>
              <span className="text-red-400 mono truncate max-w-xs" title={String(f.before)}>
                {f.before === null || f.before === undefined ? '—' : String(f.before)}
              </span>
              <span className="text-gray-600">→</span>
              <span className="text-green-400 mono truncate max-w-xs" title={String(f.after)}>
                {f.after === null || f.after === undefined ? '—' : String(f.after)}
              </span>
              <SeverityBadge severity={f.severity} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function ToolChangesPanel() {
  const [changes, setChanges] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setChanges(await fetchToolChanges(200))
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-gray-800 bg-gray-900 flex-shrink-0">
        <div>
          <p className="text-sm font-medium text-gray-200">Tool Changes</p>
          <p className="text-xs text-gray-500 mt-0.5">
            New, removed, or modified tools detected across rescans — a server that quietly
            changes behavior after being approved shows up here
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
            loading ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 text-white'
          }`}
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {error && (
          <div className="m-4 px-3 py-2 bg-red-900/40 border border-red-700 rounded text-red-400 text-sm">
            {error}
          </div>
        )}

        {!error && changes.length === 0 && (
          <p className="text-gray-600 text-sm text-center py-8">
            No tool changes detected yet. They show up after a rescan finds a difference
            from the previous discovery.
          </p>
        )}

        {changes.map((change) => <ChangeRow key={change.id} change={change} />)}
      </div>
    </div>
  )
}
