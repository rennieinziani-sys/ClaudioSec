import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { colors, font, SEV_COLOR } from '../lib/tokens';

function Clock() {
  const [time, setTime] = useState('');
  useEffect(() => {
    const tick = () => setTime(new Date().toUTCString().slice(17, 25) + ' UTC');
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span style={{ fontFamily: font.mono, fontSize: 11, color: colors.muted, letterSpacing: 2 }}>
      {time}
    </span>
  );
}

function ThreatBadge({ critical = 0, unresolved = 0 }) {
  const level = critical > 5 ? 'CRITICAL' : critical > 0 ? 'ELEVATED' : 'NOMINAL';
  const color = critical > 5 ? colors.red : critical > 0 ? colors.orange : colors.green;

  return (
    <motion.div
      key={level}
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      style={{
        fontFamily: font.mono,
        fontSize: 9,
        letterSpacing: 2,
        padding: '4px 12px',
        border: `1px solid ${color}`,
        borderRadius: 2,
        color,
        background: `${color}12`,
      }}
    >
      {level === 'CRITICAL' ? (
        <motion.span animate={{ opacity: [1, 0.4, 1] }} transition={{ repeat: Infinity, duration: 0.9 }}>
          THREAT: {level}
        </motion.span>
      ) : (
        `THREAT: ${level}`
      )}
    </motion.div>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center', minWidth: 52 }}>
      <div style={{ fontFamily: font.mono, fontSize: 8, color: colors.muted, letterSpacing: 1, marginBottom: 2 }}>
        {label}
      </div>
      <AnimatePresence mode="wait">
        <motion.div
          key={value}
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 6 }}
          transition={{ duration: 0.2 }}
          style={{ fontFamily: font.mono, fontSize: 18, fontWeight: 700, color, lineHeight: 1 }}
        >
          {value ?? '—'}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

export default function Topbar({ stats }) {
  return (
    <div style={{
      height: 48,
      background: colors.bg2,
      borderBottom: `1px solid ${colors.border}`,
      display: 'flex',
      alignItems: 'center',
      padding: '0 20px',
      gap: 18,
      position: 'relative',
      zIndex: 100,
      flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ fontFamily: font.display, fontSize: 13, fontWeight: 900, color: colors.green, letterSpacing: 4 }}>
        CLAUDIO
        <span style={{ color: colors.muted, opacity: 0.5 }}>SEC</span>
      </div>

      <div style={{ width: 1, height: 20, background: colors.border2 }} />

      {/* Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <motion.div
          animate={{ opacity: [1, 0.2, 1] }}
          transition={{ repeat: Infinity, duration: 2 }}
          style={{ width: 5, height: 5, borderRadius: '50%', background: colors.green }}
        />
        <span style={{ fontFamily: font.mono, fontSize: 9, color: colors.green, letterSpacing: 2 }}>
          ONLINE
        </span>
      </div>

      <ThreatBadge critical={stats?.critical_unresolved} unresolved={stats?.unresolved} />

      <div style={{ width: 1, height: 20, background: colors.border2 }} />

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 24 }}>
        <StatPill label="TOTAL"      value={stats?.total_events}        color={colors.green} />
        <StatPill label="CRITICAL"   value={stats?.critical_unresolved} color={colors.red} />
        <StatPill label="UNRESOLVED" value={stats?.unresolved}          color={colors.orange} />
        <StatPill label="24H"        value={stats?.last_24h}            color={colors.cyan} />
      </div>

      <div style={{ marginLeft: 'auto' }}>
        <Clock />
      </div>
    </div>
  );
}