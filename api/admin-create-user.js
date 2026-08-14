const SUPABASE_URL = 'https://dmyctkxfwzwgyroxkogb.supabase.co';

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!serviceKey) {
    res.status(500).json({ error: '서버 설정 오류입니다.' });
    return;
  }

  const authHeader = req.headers['authorization'] || '';
  const callerToken = authHeader.replace(/^Bearer\s+/i, '');
  if (!callerToken) {
    res.status(401).json({ error: '로그인이 필요합니다.' });
    return;
  }

  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6) {
    res.status(400).json({ error: '이메일과 6자 이상의 비밀번호를 입력해 주세요.' });
    return;
  }

  // 1) 호출자 신원 확인
  const callerRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: serviceKey, Authorization: `Bearer ${callerToken}` },
  });
  if (!callerRes.ok) {
    res.status(401).json({ error: '로그인 정보가 유효하지 않습니다.' });
    return;
  }
  const caller = await callerRes.json();

  // 2) 호출자가 super_admin인지 확인
  const roleRes = await fetch(
    `${SUPABASE_URL}/rest/v1/admins?user_id=eq.${caller.id}&select=role`,
    { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } }
  );
  const roleRows = await roleRes.json();
  if (!roleRes.ok || !roleRows[0] || roleRows[0].role !== 'super_admin') {
    res.status(403).json({ error: '관리자 계정을 추가할 권한이 없습니다.' });
    return;
  }

  // 3) Supabase Auth 사용자 생성
  const createRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
    method: 'POST',
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  const created = await createRes.json();
  if (!createRes.ok) {
    res.status(400).json({ error: created.msg || created.error_description || '계정 생성에 실패했습니다.' });
    return;
  }

  // 4) admins 테이블에 등록
  const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/admins`, {
    method: 'POST',
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify([{ user_id: created.id, email, role: 'admin', must_change_password: true }]),
  });
  if (!insertRes.ok) {
    const errBody = await insertRes.text();
    res.status(500).json({ error: '계정은 생성되었지만 등록에 실패했습니다: ' + errBody });
    return;
  }

  res.status(200).json({ ok: true });
};
