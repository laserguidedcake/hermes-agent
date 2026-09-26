// Private-CA trust fallback for Chromium's network stack.
//
// Electron's `net` module (and every Chromium-socket consumer: OAuth session
// requests, ws-ticket mints, page loads) verifies certificates with Chromium's
// verifier, which honors neither NODE_EXTRA_CA_CERTS nor --use-system-certificates
// on Linux. Node's tls DOES honor NODE_EXTRA_CA_CERTS, so when Chromium rejects
// a chain we re-verify the same host with node:tls and accept only if Node's
// (system + extra-CA) store validates it. Chromium's own verdict is always
// honored first; this only relaxes failures, never the reverse.
//
// The fallback arms itself only when NODE_EXTRA_CA_CERTS is set, so stock
// installs pay nothing and public-CA behavior is untouched.

import tls from 'node:tls'
import type { Session } from 'electron'

const TRUST_CACHE_MAX = 256
// host + leaf fingerprint → accepted via the Node fallback. Failures are not
// cached: a transient network error must not pin a host as untrusted.
const acceptedHosts = new Map<string, true>()

function cacheKey(hostname: string, fingerprint?: string): string {
  return `${hostname}:${fingerprint ?? 'unknown'}`
}

function probeWithNodeTls(hostname: string, port = 443): Promise<boolean> {
  return new Promise(resolve => {
    const socket = tls.connect({ host: hostname, port, servername: hostname })
    socket.once('secureConnect', () => {
      socket.end()
      resolve(true)
    })
    socket.once('error', () => {
      socket.destroy()
      resolve(false)
    })
    socket.setTimeout(10_000, () => {
      socket.destroy()
      resolve(false)
    })
  })
}

// Idempotent per session: safe to call every time an OAuth partition session
// is resolved, and once for session.defaultSession at startup.
export function applyPrivateCaTrustFallback(sess: Session): void {
  if (!process.env.NODE_EXTRA_CA_CERTS) return
  if ((sess as unknown as Record<string, unknown>).__privateCaTrustApplied) return
  ;(sess as unknown as Record<string, unknown>).__privateCaTrustApplied = true

  sess.setCertificateVerifyProc((request, callback) => {
    // Chromium's own verification passed — nothing to do.
    if (request.errorCode === 0) {
      callback(0)
      return
    }

    const fingerprint = (request.validatedCertificate ?? request.certificate)?.fingerprint
    const key = cacheKey(request.hostname, fingerprint)
    if (acceptedHosts.has(key)) {
      callback(0)
      return
    }

    probeWithNodeTls(request.hostname).then(ok => {
      if (ok) {
        if (acceptedHosts.size >= TRUST_CACHE_MAX) acceptedHosts.clear()
        acceptedHosts.set(key, true)
        callback(0)
      } else {
        callback(request.errorCode)
      }
    }, () => callback(request.errorCode))
  })
}
