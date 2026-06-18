import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'

const QUICK_TAGS = ['c2', 'ransomware', 'phishing', 'scanner', 'tor', 'botnet', 'malware', 'exploit']

const S = {
  card: { background: '#141b2d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 },
  label: { fontSize: 11, fontWeight: 700, color: '#8892a4', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 },
  input: { width: '100%', background: '#0f1629', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '9px 12px', fontSize: 13, color: '#e2e8f0', outline: 'none', fontFamily: 'inherit' },
  btn: { padding: '8px 16px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: 'pointer', border: 'none', transition: 'all 0.15s' },
}

export default function AnalystPanel({ iocValue, notes = [], tags = [] }) {
  const [noteText, setNoteText]       = useState('')
  const [tagInput, setTagInput]       = useState('')
  const [currentTags, setCurrentTags] = useState(tags)
  const [currentNotes, setNotes]      = useState(notes)
  const qc = useQueryClient()

  const addNote = useMutation({
    mutationFn: (note) => api.post(`/ioc/${encodeURIComponent(iocValue)}/notes`, { note }),
    onSuccess: (res) => {
      setNoteText('')
      setNotes(prev => [...prev, res.data])
      qc.invalidateQueries(['dashboard-stats'])
    },
  })

  const updateTags = useMutation({
    mutationFn: (newTags) => api.put(`/ioc/${encodeURIComponent(iocValue)}/tags`, { tags: newTags }),
  })

  const addTag = (raw) => {
    const t = (raw || tagInput).trim().toLowerCase()
    if (!t || currentTags.includes(t)) { setTagInput(''); return }
    const next = [...currentTags, t]
    setCurrentTags(next)
    updateTags.mutate(next)
    setTagInput('')
  }

  const removeTag = (tag) => {
    const next = currentTags.filter(t => t !== tag)
    setCurrentTags(next)
    updateTags.mutate(next)
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      {/* Tags */}
      <div style={S.card}>
        <p style={S.label}>
          <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
          </svg>
          Tags
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12, minHeight: 28 }}>
          {currentTags.map(tag => (
            <span key={tag} style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 600,
              background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', color: '#00d4ff',
            }}>
              {tag}
              <button onClick={() => removeTag(tag)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8892a4', fontSize: 14, lineHeight: 1, padding: 0 }}
                onMouseEnter={e => e.target.style.color = '#ff4444'}
                onMouseLeave={e => e.target.style.color = '#8892a4'}
              >×</button>
            </span>
          ))}
          {currentTags.length === 0 && <span style={{ fontSize: 12, color: '#8892a4' }}>No tags yet</span>}
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input
            value={tagInput}
            onChange={e => setTagInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addTag()}
            placeholder="Add tag…"
            style={S.input}
          />
          <button onClick={() => addTag()}
            style={{ ...S.btn, background: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.2)', padding: '8px 14px' }}>
            Add
          </button>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          {QUICK_TAGS.filter(t => !currentTags.includes(t)).map(tag => (
            <button key={tag} onClick={() => addTag(tag)}
              style={{ padding: '2px 9px', borderRadius: 20, fontSize: 10, cursor: 'pointer', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#8892a4' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,212,255,0.08)'; e.currentTarget.style.color = '#00d4ff' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; e.currentTarget.style.color = '#8892a4' }}
            >+ {tag}</button>
          ))}
        </div>
      </div>

      {/* Notes */}
      <div style={S.card}>
        <p style={S.label}>
          <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
          Analyst Notes
        </p>
        <div style={{ maxHeight: 140, overflowY: 'auto', marginBottom: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {currentNotes.map((n, i) => (
            <div key={n.id || i} style={{ background: '#0f1629', borderRadius: 8, padding: '8px 12px', borderLeft: '2px solid rgba(0,212,255,0.3)' }}>
              <div style={{ fontSize: 10, color: '#8892a4', marginBottom: 4 }}>
                {n.analyst} · {new Date(n.created_at).toLocaleString()}
              </div>
              <p style={{ fontSize: 12, color: '#c8d6e8', margin: 0 }}>{n.note}</p>
            </div>
          ))}
          {currentNotes.length === 0 && <p style={{ fontSize: 12, color: '#8892a4' }}>No notes yet</p>}
        </div>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation note…"
          rows={3}
          style={{ ...S.input, resize: 'none', marginBottom: 8 }}
        />
        <button
          onClick={() => noteText.trim() && addNote.mutate(noteText.trim())}
          disabled={!noteText.trim() || addNote.isPending}
          style={{ ...S.btn, background: noteText.trim() ? 'rgba(0,212,255,0.15)' : 'rgba(255,255,255,0.04)', color: noteText.trim() ? '#00d4ff' : '#8892a4', border: '1px solid rgba(0,212,255,0.2)', opacity: !noteText.trim() || addNote.isPending ? 0.5 : 1 }}
        >
          {addNote.isPending ? 'Saving…' : 'Save Note'}
        </button>
      </div>
    </div>
  )
}
