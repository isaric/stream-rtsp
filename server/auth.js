const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');

const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const COOKIE_NAME = 'auth';

function signToken(payload, expiresIn = '12h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function parseCookies(req) {
  try {
    return cookie.parse(req.headers.cookie || '');
  } catch {
    return {};
  }
}

function setAuthCookie(res, token, secure = false) {
  const serialized = cookie.serialize(COOKIE_NAME, token, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: 12 * 60 * 60, // 12h
  });
  res.setHeader('Set-Cookie', serialized);
}

function clearAuthCookie(res) {
  const serialized = cookie.serialize(COOKIE_NAME, '', {
    httpOnly: true,
    expires: new Date(0),
    path: '/',
  });
  res.setHeader('Set-Cookie', serialized);
}

async function checkPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

module.exports = {
  JWT_SECRET,
  COOKIE_NAME,
  signToken,
  verifyToken,
  parseCookies,
  setAuthCookie,
  clearAuthCookie,
  checkPassword,
};
