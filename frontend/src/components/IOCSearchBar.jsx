import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'

const IOC_PATTERNS = {
  ip:     /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]{2,}:{1,}).*$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  sha1:   /^[a-fA-F0-9]{40}$/,
  md5:    /^[a-fA-F0-9]{32}$/,
  url:    /^https?:\/\//i,
  domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
}

function detectType(value) {
  const v = value.trim()
  for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
    if (pattern.test(v)) return type
  }
  return null
}

export default function IOCSearchBar({ onResult }) {
  const [input, setInput]       = useState('')
  const [detectedType, setType] = useState(null)
  const queryClient             = useQueryClient()

  const lookupMutation = useMutation({
    mutationFn: (value) => api.post('/ioc/lookup', { value }),
    onSuccess: (data) => {
      onResult(data.data)
      queryClient.invalidateQueries(['dashboard-stats'])
    },
  })

  const handleInput = (e) => {
    const v = e.target.value
    setInput(v)
    setType(detectType(v))
  }

  const handleSubmit = () => {
    if (input.trim()) lookupMutation.mutate(input.trim())
  }

  return (
    <div className="w-full max-w-3xl">
      <div className={`flex items-center gap-3 bg-slate-900 border rounded-xl px-4 py-3 transition-colors ${
        lookupMutation.isError ? 'border-red-600' : 'border-slate-700 focus-within:border-sky-500'
      }`}>
        <svg className="w-5 h-5 text-slate-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          value={input}
          onChange={handleInput}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Enter IP, domain, URL, or file hash (MD5/SHA1/SHA256)..."
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-500 font-mono text-sm outline-none"
        />
        {detectedType && (
          <span className="px-2 py-1 rounded bg-sky-900/50 text-sky-400 text-xs font-mono uppercase flex-shrink-0">
            {detectedType}
          </span>
        )}
        <button
          onClick={handleSubmit}
          disabled={!input.trim() || lookupMutation.isPending}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-40 rounded-lg text-white text-sm font-medium transition-colors flex-shrink-0"
        >
          {lookupMutation.isPending ? 'Querying...' : 'Lookup'}
        </button>
      </div>
      {lookupMutation.isPending && (
        <p className="mt-2 text-xs text-slate-400 animate-pulse">
          ⚡ Querying 5 threat intel sources in parallel...
        </p>
      )}
      {lookupMutation.isError && (
        <p className="mt-2 text-xs text-red-400">
          {lookupMutation.error?.message}
        </p>
      )}
    </div>
  )
}
