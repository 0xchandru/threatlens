import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'

export default function AnalystPanel({ iocValue, notes = [], tags = [] }) {
  const [noteText, setNoteText]   = useState('')
  const [tagInput, setTagInput]   = useState('')
  const [currentTags, setCurrentTags] = useState(tags)
  const qc = useQueryClient()

  const addNote = useMutation({
    mutationFn: (note) => api.post(`/ioc/${encodeURIComponent(iocValue)}/notes`, { note }),
    onSuccess: () => {
      setNoteText('')
      qc.invalidateQueries(['ioc-detail', iocValue])
    },
  })

  const updateTags = useMutation({
    mutationFn: (newTags) => api.put(`/ioc/${encodeURIComponent(iocValue)}/tags`, { tags: newTags }),
    onSuccess: (_, newTags) => setCurrentTags(newTags),
  })

  const addTag = () => {
    const t = tagInput.trim().toLowerCase()
    if (t && !currentTags.includes(t)) {
      const next = [...currentTags, t]
      setCurrentTags(next)
      updateTags.mutate(next)
    }
    setTagInput('')
  }

  const removeTag = (tag) => {
    const next = currentTags.filter(t => t !== tag)
    setCurrentTags(next)
    updateTags.mutate(next)
  }

  return (
    <div className="space-y-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Tags</h3>
        <div className="flex flex-wrap gap-2 mb-3">
          {currentTags.map(tag => (
            <span key={tag}
              className="flex items-center gap-1 px-2 py-1 rounded-full bg-slate-700 text-slate-300 text-xs">
              {tag}
              <button onClick={() => removeTag(tag)}
                className="text-slate-500 hover:text-red-400 transition-colors">×</button>
            </span>
          ))}
          {currentTags.length === 0 && <span className="text-xs text-slate-500">No tags yet</span>}
        </div>
        <div className="flex gap-2">
          <input
            value={tagInput}
            onChange={e => setTagInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addTag()}
            placeholder="Add tag (e.g. c2, ransomware)"
            className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500"
          />
          <button onClick={addTag}
            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-slate-300 transition-colors">
            Add
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Analyst Notes</h3>
        <div className="space-y-3 mb-3 max-h-48 overflow-y-auto">
          {notes.map(n => (
            <div key={n.id} className="bg-slate-800 rounded-lg p-3">
              <div className="text-xs text-slate-500 mb-1">
                {n.analyst} · {new Date(n.created_at).toLocaleString()}
              </div>
              <p className="text-sm text-slate-300">{n.note}</p>
            </div>
          ))}
          {notes.length === 0 && <p className="text-xs text-slate-500">No notes yet</p>}
        </div>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation note..."
          rows={3}
          className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500 resize-none"
        />
        <button
          onClick={() => noteText.trim() && addNote.mutate(noteText.trim())}
          disabled={!noteText.trim() || addNote.isPending}
          className="mt-2 px-4 py-2 bg-sky-700 hover:bg-sky-600 disabled:opacity-40 rounded-lg text-sm text-white transition-colors"
        >
          {addNote.isPending ? 'Saving...' : 'Save Note'}
        </button>
      </div>
    </div>
  )
}
