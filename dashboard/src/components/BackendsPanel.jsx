import { useState, useEffect, useCallback } from 'react'
import {
  fetchBackends, addBackend, deleteBackend, resetRuntimeState, triggerRescan,
  setLabelOverride, clearLabelOverride,
} from '../api'

const ALL_LABELS = ['U', 'S', 'E']

const LABEL_STYLES = {
  U: 'bg-purple-900 text-purple-200 border border-purple-700',
  S: 'bg-blue-900 text-blue-200 border border-blue-800',
  E: 'bg-red-900 text-red-200 border border-red-800',
}

function LabelBadge({ label }) {
  const style = LABEL_STYLES[label] ?? 'bg-gray-800 text-gray-400'
  return (
    <span
      className={`text-xs px-1.5 py-0.5 rounded font-bold mono ${style}`}
      title={label === 'U' ? 'Untrusted Input' : label === 'S' ? 'Sensitive Access' : 'External Output'}
    >
      {label}
    </span>
  )
}

function StatusDot({ status }) {
  const color = status === 'running' ? 'bg-green-500' : 'bg-red-500'
  return <span className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />
}

function ToolRow({ tool, onSetOverride, onClearOverride }) {
  const [editing, setEditing] = useState(false)
  const [selected, setSelected] = useState(tool.labels || [])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!editing) setSelected(tool.labels || [])
  }, [tool.labels, editing])

  const toggle = (label) => {
    setSelected((prev) => (prev.includes(label) ? prev.filter((l) => l !== label) : [...prev, label]))
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSetOverride(tool.name, selected)
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  const handleReset = async () => {
    setSaving(true)
    try {
      await onClearOverride(tool.name)
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-start gap-2 py-1.5 border-t border-gray-800/60 first:border-t-0">
      <span className="mono text-xs text-gray-300 flex-shrink-0 w-44 truncate" title={tool.name}>
        {tool.name}
      </span>
      <span className="text-xs text-gray-500 flex-1 leading-snug">{tool.description || '—'}</span>

      {!editing ? (
        <div className="flex items-center gap-1 flex-shrink-0">
          {tool.labels?.map((l) => <LabelBadge key={l} label={l} />)}
          {tool.labels?.length === 0 && <span className="text-xs text-gray-700">no labels</span>}
          {tool.overridden && (
            <span className="text-xs text-amber-400" title="Manually overridden">✎</span>
          )}
          <button
            onClick={() => setEditing(true)}
            className="text-gray-600 hover:text-gray-300 transition-colors ml-1"
            title="Edit labels"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" className="w-3.5 h-3.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487z" />
            </svg>
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-1 flex-shrink-0">
          {ALL_LABELS.map((l) => (
            <button
              key={l}
              type="button"
              onClick={() => toggle(l)}
              className={`text-xs px-1.5 py-0.5 rounded font-bold mono border transition-colors ${
                selected.includes(l) ? LABEL_STYLES[l] : 'bg-gray-800 text-gray-600 border-gray-700'
              }`}
            >
              {l}
            </button>
          ))}
          <button
            onClick={handleSave}
            disabled={saving}
            className="text-xs text-blue-400 hover:text-blue-300 ml-1 disabled:opacity-40"
          >
            Save
          </button>
          {tool.overridden && (
            <button
              onClick={handleReset}
              disabled={saving}
              className="text-xs text-gray-500 hover:text-gray-300 disabled:opacity-40"
            >
              Reset
            </button>
          )}
          <button
            onClick={() => { setEditing(false); setSelected(tool.labels || []) }}
            className="text-xs text-gray-600 hover:text-gray-400"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  )
}

function BackendCard({ backend, onDelete, deleting, onSetOverride, onClearOverride }) {
  const [expanded, setExpanded] = useState(false)
  const toolCount = backend.tools?.length ?? 0

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <button
          className="flex items-center gap-2 min-w-0"
          onClick={() => setExpanded((e) => !e)}
          title={expanded ? 'Collapse' : 'Expand tools'}
        >
          <svg
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
            className={`w-3.5 h-3.5 text-gray-600 flex-shrink-0 transition-transform ${expanded ? 'rotate-90' : ''}`}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
          </svg>
          <StatusDot status={backend.status ?? 'running'} />
          <span className="font-medium text-gray-200 truncate">{backend.name}</span>
          <span className="text-xs text-gray-600 flex-shrink-0">
            {toolCount} tool{toolCount === 1 ? '' : 's'}
          </span>
        </button>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">
            {backend.transport ?? 'stdio'}
          </span>
          <button
            onClick={() => onDelete(backend.name)}
            disabled={deleting}
            className="text-gray-600 hover:text-red-400 transition-colors disabled:opacity-40"
            title="Remove server"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" className="w-4 h-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
            </svg>
          </button>
        </div>
      </div>

      <div className="space-y-1.5 text-sm">
        {backend.command && (
          <div className="flex gap-2">
            <span className="text-gray-600 w-20 flex-shrink-0">Command</span>
            <span className="mono text-gray-300">{backend.command}</span>
          </div>
        )}
        {backend.args?.length > 0 && (
          <div className="flex gap-2">
            <span className="text-gray-600 w-20 flex-shrink-0">Args</span>
            <span className="mono text-gray-400 text-xs">{backend.args.join(' ')}</span>
          </div>
        )}
        {backend.url && (
          <div className="flex gap-2">
            <span className="text-gray-600 w-20 flex-shrink-0">URL</span>
            <span className="mono text-gray-300">{backend.url}</span>
          </div>
        )}
      </div>

      {expanded && (
        <div className="mt-3 pt-1 border-t border-gray-800">
          {toolCount === 0 && (
            <p className="text-xs text-gray-600 py-2">No tools discovered yet.</p>
          )}
          {backend.tools?.map((tool) => (
            <ToolRow
              key={tool.name}
              tool={tool}
              onSetOverride={onSetOverride}
              onClearOverride={onClearOverride}
            />
          ))}
        </div>
      )}
    </div>
  )
}

const DEFAULT_NEW_SERVER = {
  name: '',
  transport: 'stdio',
  command: '',
  args: '',
  url: '',
}

function AddServerForm({ onAdd, onCancel }) {
  const [form, setForm] = useState(DEFAULT_NEW_SERVER)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.name.trim()) {
      setError('Name is required.')
      return
    }
    const payload = {
      name: form.name.trim(),
      transport: form.transport,
      ...(form.transport === 'stdio'
        ? { command: form.command.trim(), args: form.args.trim() ? form.args.trim().split(/\s+/) : [] }
        : { url: form.url.trim() }),
    }
    setSubmitting(true)
    setError(null)
    try {
      await onAdd(payload)
      setForm(DEFAULT_NEW_SERVER)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-200">Add MCP Server</p>
        <button type="button" onClick={onCancel} className="text-xs text-gray-500 hover:text-gray-300">
          Cancel
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <label className="text-xs text-gray-500 space-y-1">
          <span>Name</span>
          <input
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-sm text-gray-200 mono"
            placeholder="my-server"
          />
        </label>
        <label className="text-xs text-gray-500 space-y-1">
          <span>Transport</span>
          <select
            value={form.transport}
            onChange={(e) => set('transport', e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-sm text-gray-200"
          >
            <option value="stdio">stdio</option>
            <option value="http">http</option>
          </select>
        </label>
      </div>

      {form.transport === 'stdio' ? (
        <div className="grid grid-cols-2 gap-3">
          <label className="text-xs text-gray-500 space-y-1">
            <span>Command</span>
            <input
              value={form.command}
              onChange={(e) => set('command', e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-sm text-gray-200 mono"
              placeholder="./.venv/bin/python"
            />
          </label>
          <label className="text-xs text-gray-500 space-y-1">
            <span>Args (space-separated)</span>
            <input
              value={form.args}
              onChange={(e) => set('args', e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-sm text-gray-200 mono"
              placeholder="tests/mock_mcp_server.py"
            />
          </label>
        </div>
      ) : (
        <label className="text-xs text-gray-500 space-y-1 block">
          <span>URL</span>
          <input
            value={form.url}
            onChange={(e) => set('url', e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-sm text-gray-200 mono"
            placeholder="http://localhost:3002/sse"
          />
        </label>
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}

      <button
        type="submit"
        disabled={submitting}
        className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
          submitting ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 text-white'
        }`}
      >
        {submitting ? 'Adding…' : 'Add Server'}
      </button>
    </form>
  )
}

export default function BackendsPanel({ onRescan, onRuntimeReset }) {
  const [backends, setBackends] = useState([])
  const [error, setError] = useState(null)
  const [rescanning, setRescanning] = useState(false)
  const [rescanMsg, setRescanMsg] = useState(null)
  const [resetting, setResetting] = useState(false)
  const [showAddForm, setShowAddForm] = useState(false)
  const [deletingName, setDeletingName] = useState(null)

  const load = useCallback(async () => {
    try {
      setBackends(await fetchBackends())
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleRescan = async () => {
    setRescanning(true)
    setRescanMsg(null)
    try {
      await triggerRescan()
      setRescanMsg('Rescan triggered — discovery and toxic flow analysis are running in the background.')
      onRescan?.()
      setTimeout(load, 1500)
    } catch (e) {
      setRescanMsg(`Rescan failed: ${e.message}`)
    } finally {
      setRescanning(false)
    }
  }

  const handleResetRuntime = async () => {
    const confirmed = window.confirm(
      'Clear stored demo sessions, events, and cached analysis results? This cannot be undone.'
    )
    if (!confirmed) return

    setResetting(true)
    setRescanMsg(null)
    try {
      const result = await resetRuntimeState()
      setRescanMsg(
        `Runtime data cleared — removed ${result.deleted_sessions} sessions and ${result.deleted_events} events.`
      )
      await load()
      onRuntimeReset?.()
    } catch (e) {
      setRescanMsg(`Reset failed: ${e.message}`)
    } finally {
      setResetting(false)
    }
  }

  const handleAdd = async (payload) => {
    const result = await addBackend(payload)
    if (result.live && result.discovery) {
      const { tool_count, labels } = result.discovery
      const riskyLabels = Object.values(labels || {}).flat().filter(Boolean)
      setRescanMsg(
        `Added '${result.name}' — ${tool_count} tool(s) discovered` +
        (riskyLabels.length ? `, labeled: ${[...new Set(riskyLabels)].join(', ')}.` : '.')
      )
    } else if (result.live_error) {
      setRescanMsg(`Added '${result.name}' to config — ${result.live_error}`)
    }
    setShowAddForm(false)
    await load()
  }

  const handleSetOverride = async (toolName, labels) => {
    try {
      await setLabelOverride(toolName, labels)
      await load()
    } catch (e) {
      setRescanMsg(`Failed to set override for '${toolName}': ${e.message}`)
    }
  }

  const handleClearOverride = async (toolName) => {
    try {
      await clearLabelOverride(toolName)
      await load()
    } catch (e) {
      setRescanMsg(`Failed to reset override for '${toolName}': ${e.message}`)
    }
  }

  const handleDelete = async (name) => {
    const confirmed = window.confirm(`Remove MCP server '${name}'?`)
    if (!confirmed) return
    setDeletingName(name)
    setRescanMsg(null)
    try {
      const result = await deleteBackend(name)
      setRescanMsg(
        result.live
          ? `Removed '${name}' — stopped live and out of the routing table.`
          : `Removed '${name}' from config — ${result.live_error ?? 'will take effect on next launch.'}`
      )
      await load()
    } catch (e) {
      setRescanMsg(`Remove failed: ${e.message}`)
    } finally {
      setDeletingName(null)
    }
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-gray-800 bg-gray-900 flex-shrink-0">
        <div>
          <p className="text-sm font-medium text-gray-200">MCP Servers</p>
          <p className="text-xs text-gray-500 mt-0.5">
            Backends connected through the proxy, and the tools each one exposes
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleResetRuntime}
            disabled={resetting}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              resetting
                ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                : 'bg-red-900 hover:bg-red-800 text-red-100'
            }`}
          >
            {resetting ? 'Clearing…' : 'Clear Demo Data'}
          </button>
          <button
            onClick={handleRescan}
            disabled={rescanning}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              rescanning
                ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-500 text-white'
            }`}
          >
            <svg
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
              className={`w-4 h-4 ${rescanning ? 'animate-spin' : ''}`}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
            </svg>
            {rescanning ? 'Scanning…' : 'Rescan'}
          </button>
          <button
            onClick={() => setShowAddForm((s) => !s)}
            className="px-4 py-1.5 rounded text-sm font-medium transition-colors bg-green-700 hover:bg-green-600 text-white"
          >
            {showAddForm ? 'Close' : '+ Add Server'}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-3">
        {error && (
          <div className="px-3 py-2 bg-red-900/40 border border-red-700 rounded text-red-400 text-sm">
            {error}
          </div>
        )}

        {rescanMsg && (
          <div className="px-3 py-2 bg-blue-900/40 border border-blue-700 rounded text-blue-300 text-sm">
            {rescanMsg}
          </div>
        )}

        {showAddForm && (
          <AddServerForm onAdd={handleAdd} onCancel={() => setShowAddForm(false)} />
        )}

        {backends.length === 0 && !error && (
          <p className="text-gray-600 text-sm text-center py-8">
            No backends found. Add one above, or check mcpsec-config.yaml.
          </p>
        )}

        {backends.map((backend) => (
          <BackendCard
            key={backend.name}
            backend={backend}
            onDelete={handleDelete}
            deleting={deletingName === backend.name}
            onSetOverride={handleSetOverride}
            onClearOverride={handleClearOverride}
          />
        ))}

        {/* Info box */}
        <div className="mt-4 px-4 py-3 bg-gray-900 border border-gray-800 rounded-lg">
          <p className="text-xs text-gray-500 font-medium mb-1">How this works</p>
          <p className="text-xs text-gray-600 leading-relaxed">
            Adding a server spawns it immediately and re-runs discovery + Toxic Flow analysis,
            so its tools and U/S/E risk labels appear right away — no restart needed.
            Removing a server stops it live when the proxy is running; if it can't be stopped
            live, it's still removed from config and will be gone on the next restart.
            Rescan rebuilds the routing table and re-runs discovery for all servers.
          </p>
        </div>
      </div>
    </div>
  )
}
