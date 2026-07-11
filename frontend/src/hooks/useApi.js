import { useState, useEffect, useRef, useCallback } from 'react';

const API = '';

export function useStats() {
  const [stats, setStats] = useState(null);
  const [sysStats, setSysStats] = useState(null);

  const fetch_ = useCallback(async () => {
    try {
      const [s, sys] = await Promise.all([
        fetch(API + '/api/stats').then(r => r.json()),
        fetch(API + '/api/system/stats').then(r => r.json()),
      ]);
      setStats(s);
      setSysStats(sys);
    } catch (e) {}
  }, []);

  useEffect(() => {
    fetch_();
    const t = setInterval(fetch_, 8000);
    return () => clearInterval(t);
  }, [fetch_]);

  return { stats, sysStats, refresh: fetch_ };
}

export function useEvents(severity = null) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetch_ = useCallback(async () => {
    try {
      let url = API + '/api/events?limit=80';
      if (severity && severity !== 'all') url += '&severity=' + severity;
      const d = await fetch(url).then(r => r.json());
      setEvents(d.events || []);
    } catch (e) {}
    finally { setLoading(false); }
  }, [severity]);

  useEffect(() => {
    fetch_();
    const t = setInterval(fetch_, 8000);
    return () => clearInterval(t);
  }, [fetch_]);

  return { events, loading, refresh: fetch_ };
}

export function useWebSocket(onEvent) {
  const ws = useRef(null);

  useEffect(() => {
    function connect() {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      ws.current = new WebSocket(`${proto}://${window.location.host}/ws`);
      ws.current.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          onEvent(msg);
        } catch (_) {}
      };
      ws.current.onclose = () => setTimeout(connect, 3000);
    }
    connect();
    return () => ws.current?.close();
  }, [onEvent]);
}

export async function analyzeEvent(id) {
  const r = await fetch(API + `/api/events/${id}/analyze`, { method: 'POST' });
  return r.json();
}

export async function sendChatMessage(messages) {
  const r = await fetch(API + '/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages }),
  });
  return r.json();
}

export async function generateReport() {
  const r = await fetch(API + '/api/reports/generate', { method: 'POST' });
  return r.json();
}