/**
 * AuthField — a labelled input for the auth forms.
 * Supports an optional password visibility toggle and inline error text.
 */
import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'

export default function AuthField({
  id,
  label,
  type = 'text',
  value,
  onChange,
  placeholder,
  autoComplete,
  error,
  hint,
  icon: Icon,
  autoFocus = false,
}) {
  const [show, setShow] = useState(false)
  const isPassword = type === 'password'
  const inputType = isPassword && show ? 'text' : type

  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-gray-300">
        {label}
      </label>
      <div className="relative">
        {Icon && (
          <Icon
            size={16}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
          />
        )}
        <input
          id={id}
          name={id}
          type={inputType}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          aria-invalid={!!error}
          aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
          className={`
            w-full rounded-lg border bg-[#0d1220] py-2.5 text-sm text-gray-100
            placeholder:text-gray-600 outline-none transition-colors
            ${Icon ? 'pl-9' : 'pl-3'} ${isPassword ? 'pr-10' : 'pr-3'}
            ${error
              ? 'border-red-500/70 focus:border-red-400 focus:ring-2 focus:ring-red-500/20'
              : 'border-cyber-border focus:border-cyber-accent focus:ring-2 focus:ring-cyber-accent/20'}
          `}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-gray-500 hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-cyber-accent/40"
            aria-label={show ? 'Hide password' : 'Show password'}
          >
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        )}
      </div>
      {error ? (
        <p id={`${id}-error`} className="mt-1.5 text-xs text-red-400">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="mt-1.5 text-xs text-gray-500">
          {hint}
        </p>
      ) : null}
    </div>
  )
}
