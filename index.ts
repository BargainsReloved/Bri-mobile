import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return json({ error: 'POST required' }, 405)

  try {
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace(/^Bearer\s+/i, '').trim()
    if (!token) return json({ error: 'Not signed in' }, 401)

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    const { data: callerData, error: callerError } = await adminClient.auth.getUser(token)
    if (callerError || !callerData.user) return json({ error: 'Invalid sign-in session' }, 401)

    const callerId = callerData.user.id
    const { data: callerProfile, error: profileError } = await adminClient
      .from('user_profiles')
      .select('is_admin')
      .eq('auth_user_id', callerId)
      .maybeSingle()

    if (profileError || !callerProfile?.is_admin) {
      return json({ error: 'Administrator access required' }, 403)
    }

    const body = await req.json()
    const action = String(body?.action || '')

    if (action === 'create') {
      const username = String(body?.username || '').trim().toLowerCase()
      const displayName = String(body?.display_name || '').trim()
      const password = String(body?.password || '')

      if (!/^[a-z0-9._-]{2,40}$/.test(username)) {
        return json({ error: 'Invalid login name' }, 400)
      }
      if (!displayName) return json({ error: 'Display name is required' }, 400)
      if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400)

      const { data: existingProfile } = await adminClient
        .from('user_profiles')
        .select('auth_user_id')
        .eq('username', username)
        .maybeSingle()
      if (existingProfile) return json({ error: 'That login name is already in use' }, 409)

      // Internal email is never shown to the user; BRI login uses username.
      const email = `${username}@bri.local`
      const { data: created, error: createError } = await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { username, display_name: displayName },
      })
      if (createError || !created.user) {
        return json({ error: createError?.message || 'Unable to create user' }, 400)
      }

      const { error: insertError } = await adminClient.from('user_profiles').insert({
        auth_user_id: created.user.id,
        username,
        display_name: displayName,
        is_admin: false,
      })

      if (insertError) {
        await adminClient.auth.admin.deleteUser(created.user.id)
        return json({ error: insertError.message }, 400)
      }

      return json({ ok: true, username })
    }

    if (action === 'reset_password') {
      const userId = String(body?.user_id || '')
      const password = String(body?.password || '')
      if (!userId) return json({ error: 'User ID is required' }, 400)
      if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400)
      if (userId === callerId) return json({ error: 'Use your normal account settings to change your own password' }, 400)

      const { error } = await adminClient.auth.admin.updateUserById(userId, { password })
      if (error) return json({ error: error.message }, 400)
      return json({ ok: true })
    }

    if (action === 'delete') {
      const userId = String(body?.user_id || '')
      if (!userId) return json({ error: 'User ID is required' }, 400)
      if (userId === callerId) return json({ error: 'You cannot delete your own administrator account' }, 400)

      const { error } = await adminClient.auth.admin.deleteUser(userId)
      if (error) return json({ error: error.message }, 400)
      return json({ ok: true })
    }

    return json({ error: 'Unknown action' }, 400)
  } catch (error) {
    console.error(error)
    return json({ error: error instanceof Error ? error.message : 'Unexpected error' }, 500)
  }
})
