/**
 * AuthScreen — the gate in front of the dashboard.
 *
 * A small state machine over four views:
 *   login  -> sign in
 *   signup -> create account
 *   forgot -> request a reset token
 *   reset  -> set a new password with that token
 *
 * Validation mirrors the backend rules so users get instant, specific feedback.
 * The forgot/reset flow works without a mail server: the backend returns a
 * single-use demo token which we carry straight into the reset step.
 */
import { useState } from 'react'
import { Mail, Lock, User, KeyRound, ArrowRight, ArrowLeft, CheckCircle2, Info } from 'lucide-react'
import AuthLayout from './AuthLayout'
import AuthField from './AuthField'
import { useAuth } from '../../context/AuthContext'
import { apiForgotPassword, apiResetPassword, errMessage } from '../../api'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
const isEmail = (v) => EMAIL_RE.test((v || '').trim())
const isStrong = (v) => v.length >= 8 && /[A-Za-z]/.test(v) && /\d/.test(v)

function SubmitButton({ children, loading, loadingLabel }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="group flex w-full items-center justify-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyber-accent/50 disabled:cursor-not-allowed disabled:opacity-60"
    >
      {loading ? (
        <>
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyber-bg/40 border-t-cyber-bg" />
          {loadingLabel}
        </>
      ) : (
        <>
          {children}
          <ArrowRight size={16} className="transition-transform group-hover:translate-x-0.5" />
        </>
      )}
    </button>
  )
}

function FormError({ children }) {
  if (!children) return null
  return (
    <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
      <Info size={16} className="mt-0.5 shrink-0" />
      <span>{children}</span>
    </div>
  )
}

function SwitchLink({ prompt, action, onClick }) {
  return (
    <p className="text-center text-sm text-gray-400">
      {prompt}{' '}
      <button
        type="button"
        onClick={onClick}
        className="font-medium text-cyber-accent hover:text-cyan-300 focus:outline-none focus:underline"
      >
        {action}
      </button>
    </p>
  )
}

export default function AuthScreen({ serverStatus }) {
  const { login, signup, applySession } = useAuth()
  const [mode, setMode] = useState('login')

  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [resetToken, setResetToken] = useState('')
  const [newPassword, setNewPassword] = useState('')

  const [errors, setErrors] = useState({})
  const [formError, setFormError] = useState('')
  const [notice, setNotice] = useState('')
  const [demoNote, setDemoNote] = useState('')
  const [loading, setLoading] = useState(false)

  const go = (next) => {
    setMode(next)
    setErrors({})
    setFormError('')
    setNotice('')
  }

  // -------------------------------------------------- submit handlers
  const submitLogin = async (e) => {
    e.preventDefault()
    const errs = {}
    if (!isEmail(email)) errs.email = 'Enter a valid email address.'
    if (!password) errs.password = 'Enter your password.'
    setErrors(errs)
    if (Object.keys(errs).length) return

    setLoading(true)
    setFormError('')
    const res = await login(email.trim(), password)
    setLoading(false)
    if (!res.ok) setFormError(res.error)
  }

  const submitSignup = async (e) => {
    e.preventDefault()
    const errs = {}
    if (!fullName.trim()) errs.fullName = 'Enter your name.'
    if (!isEmail(email)) errs.email = 'Enter a valid email address.'
    if (!isStrong(password)) errs.password = 'At least 8 characters, with a letter and a number.'
    if (confirm !== password) errs.confirm = 'Passwords do not match.'
    setErrors(errs)
    if (Object.keys(errs).length) return

    setLoading(true)
    setFormError('')
    const res = await signup(fullName.trim(), email.trim(), password)
    setLoading(false)
    if (!res.ok) setFormError(res.error)
  }

  const submitForgot = async (e) => {
    e.preventDefault()
    const errs = {}
    if (!isEmail(email)) errs.email = 'Enter a valid email address.'
    setErrors(errs)
    if (Object.keys(errs).length) return

    setLoading(true)
    setFormError('')
    try {
      const res = await apiForgotPassword(email.trim())
      const data = res.data || {}
      if (data.demo_reset_token) {
        // No mail server in this build — carry the token straight to reset.
        setResetToken(data.demo_reset_token)
        setDemoNote(data.demo_note || '')
        setNotice('Reset token generated. Set a new password below.')
        setMode('reset')
        setErrors({})
      } else {
        setNotice('If an account exists for that email, a reset link is on its way.')
      }
    } catch (err) {
      setFormError(errMessage(err))
    } finally {
      setLoading(false)
    }
  }

  const submitReset = async (e) => {
    e.preventDefault()
    const errs = {}
    if (!resetToken.trim()) errs.resetToken = 'Paste the reset token you were given.'
    if (!isStrong(newPassword)) errs.newPassword = 'At least 8 characters, with a letter and a number.'
    setErrors(errs)
    if (Object.keys(errs).length) return

    setLoading(true)
    setFormError('')
    try {
      const res = await apiResetPassword(resetToken.trim(), newPassword)
      // Reset succeeds -> backend returns a fresh session; sign in directly.
      applySession(res.data.access_token, res.data.user)
    } catch (err) {
      setFormError(errMessage(err))
      setLoading(false)
    }
  }

  // -------------------------------------------------- view config
  const copy = {
    login: { title: 'Sign in', subtitle: 'Access the CPEDS-X operations console.' },
    signup: { title: 'Create your account', subtitle: 'Set up access to the detection console.' },
    forgot: { title: 'Reset your password', subtitle: 'We’ll issue a single-use reset token.' },
    reset: { title: 'Set a new password', subtitle: 'Choose a strong password to finish.' },
  }[mode]

  return (
    <AuthLayout title={copy.title} subtitle={copy.subtitle} serverStatus={serverStatus}>
      {notice && (
        <div className="mb-5 flex items-start gap-2 rounded-lg border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-2.5 text-sm text-cyan-200">
          <CheckCircle2 size={16} className="mt-0.5 shrink-0" />
          <span>{notice}</span>
        </div>
      )}

      {/* ---------------- LOGIN ---------------- */}
      {mode === 'login' && (
        <form onSubmit={submitLogin} className="space-y-4" noValidate>
          <FormError>{formError}</FormError>
          <AuthField
            id="email" label="Email" type="email" icon={Mail}
            value={email} onChange={setEmail} placeholder="you@company.com"
            autoComplete="email" error={errors.email} autoFocus
          />
          <div>
            <AuthField
              id="password" label="Password" type="password" icon={Lock}
              value={password} onChange={setPassword} placeholder="••••••••"
              autoComplete="current-password" error={errors.password}
            />
            <div className="mt-1.5 flex justify-end">
              <button
                type="button"
                onClick={() => go('forgot')}
                className="text-xs font-medium text-cyber-accent hover:text-cyan-300 focus:outline-none focus:underline"
              >
                Forgot password?
              </button>
            </div>
          </div>
          <SubmitButton loading={loading} loadingLabel="Signing in…">Sign in</SubmitButton>
          <SwitchLink prompt="New to CPEDS-X?" action="Create an account" onClick={() => go('signup')} />
        </form>
      )}

      {/* ---------------- SIGNUP ---------------- */}
      {mode === 'signup' && (
        <form onSubmit={submitSignup} className="space-y-4" noValidate>
          <FormError>{formError}</FormError>
          <AuthField
            id="fullName" label="Full name" icon={User}
            value={fullName} onChange={setFullName} placeholder="Alex Rivera"
            autoComplete="name" error={errors.fullName} autoFocus
          />
          <AuthField
            id="email" label="Email" type="email" icon={Mail}
            value={email} onChange={setEmail} placeholder="you@company.com"
            autoComplete="email" error={errors.email}
          />
          <AuthField
            id="password" label="Password" type="password" icon={Lock}
            value={password} onChange={setPassword} placeholder="At least 8 characters"
            autoComplete="new-password" error={errors.password}
            hint={!errors.password ? 'Use 8+ characters with a letter and a number.' : undefined}
          />
          <AuthField
            id="confirm" label="Confirm password" type="password" icon={Lock}
            value={confirm} onChange={setConfirm} placeholder="Re-enter your password"
            autoComplete="new-password" error={errors.confirm}
          />
          <SubmitButton loading={loading} loadingLabel="Creating account…">Create account</SubmitButton>
          <SwitchLink prompt="Already have an account?" action="Sign in" onClick={() => go('login')} />
        </form>
      )}

      {/* ---------------- FORGOT ---------------- */}
      {mode === 'forgot' && (
        <form onSubmit={submitForgot} className="space-y-4" noValidate>
          <FormError>{formError}</FormError>
          <AuthField
            id="email" label="Email" type="email" icon={Mail}
            value={email} onChange={setEmail} placeholder="you@company.com"
            autoComplete="email" error={errors.email} autoFocus
          />
          <SubmitButton loading={loading} loadingLabel="Sending…">Send reset token</SubmitButton>
          <button
            type="button"
            onClick={() => go('login')}
            className="flex w-full items-center justify-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 focus:outline-none"
          >
            <ArrowLeft size={14} /> Back to sign in
          </button>
        </form>
      )}

      {/* ---------------- RESET ---------------- */}
      {mode === 'reset' && (
        <form onSubmit={submitReset} className="space-y-4" noValidate>
          <FormError>{formError}</FormError>
          {demoNote && (
            <div className="rounded-lg border border-cyber-border bg-[#0d1220] px-3 py-2.5 text-xs text-gray-400">
              <span className="font-mono-soc uppercase tracking-widest text-gray-500">Demo mode</span>
              <p className="mt-1">{demoNote}</p>
            </div>
          )}
          <AuthField
            id="resetToken" label="Reset token" icon={KeyRound}
            value={resetToken} onChange={setResetToken} placeholder="Paste your reset token"
            error={errors.resetToken}
          />
          <AuthField
            id="newPassword" label="New password" type="password" icon={Lock}
            value={newPassword} onChange={setNewPassword} placeholder="At least 8 characters"
            autoComplete="new-password" error={errors.newPassword}
            hint={!errors.newPassword ? 'Use 8+ characters with a letter and a number.' : undefined}
          />
          <SubmitButton loading={loading} loadingLabel="Updating…">Set new password</SubmitButton>
          <button
            type="button"
            onClick={() => go('login')}
            className="flex w-full items-center justify-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 focus:outline-none"
          >
            <ArrowLeft size={14} /> Back to sign in
          </button>
        </form>
      )}
    </AuthLayout>
  )
}
