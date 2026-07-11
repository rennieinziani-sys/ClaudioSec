import React from 'react';
import { motion } from 'framer-motion';
import { colors, font } from '../lib/tokens';

function SectionLabel({ children }) {
  return (
    <div style={{
      fontFamily: font.mono,
      fontSize: 8,
      color: colors.muted,
      letterSpacing: 3,
      textTransform: 'uppercase',
      marginBottom: 12,
    }}>
      {children}
    </div>
  );
}

function Meter({ label, value = 0 }) {
  const danger = value > 85;
  const color = danger ? colors.red : value > 65 ? colors.orange : colors.green;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontFamily: font.mono, fontSize: 8, color: colors.muted, letterSpacing: 1 }}>{label}</span>
        <span style={{ fontFamily: font.mono, fontSize: 9, color }}>
          {typeof value === 'number' ? value.toFixed(0) + '%' : value}
        </span>
      </div>
      <div style={{ height: 2, background: colors.dim, borderRadius: 1, overflow: 'hidden' }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(value, 100)}%` }}
          transition={{ duration: 1, ease: 'easeOut' }}
          style={{ height: '100%', background: color, borderRadius: 1 }}
        />
      </div>
    </div>
  );
}

function BigStat({ label, value, color }) {
  return (
    <div>
      <div style={{ fontFamily: font.mono, fontSize: 8, color: colors.muted, letterSpacing: 1, marginBottom: 2 }}>
        {label}
      </div>
      <motion.div
        key={value}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        style={{ fontFamily: font.mono, fontSize: 24, fontWeight: 700, color, lineHeight: 1 }}
      >
        {value ?? '—'}
      </motion.div>
    </div>
  );
}

function ActionBtn({ children, primary, onClick }) {
  const [hover, setHover] = React.useState(false);
  return (
    <motion.button
      onHoverStart={() => setHover(true)}
      onHoverEnd={() => setHover(false)}
      whileTap={{ scale: 0.97 }}
      onClick={onClick}
      style={{
        display: 'block',
        width: '100%',
        padding: '8px 10px',
        marginBottom: 5,
        background: hover ? colors.greenGlow : primary ? `${colors.green}10` : 'transparent',
        border: `1px solid ${hover || primary ? colors.green : colors.border2}`,
        color: hover || primary ? colors.green : colors.muted,
        fontFamily: font.mono,
        fontSize: 9,
        letterSpacing: 2,
        textTransform: 'uppercase',
        textAlign: 'left',
        cursor: 'pointer',
        borderRadius: 2,
        transition: 'all 0.12s',
      }}
    >
      {children}
    </motion.button>
  );
}

export default function Sidebar({ stats, sysStats, onGenerateReport, onFilterCritical, onFilterAll }) {
  const cpu  = stats?.system?.cpu_percent    ?? sysStats?.cpu_percent    ?? 0;
  const mem  = stats?.system?.memory_percent ?? sysStats?.memory?.percent ?? 0;
  const disk = sysStats?.disk?.percent ?? 0;
  const proc = sysStats?.processes ?? '—';

  return (
    <div style={{
      width: 200,
      background: colors.bg2,
      borderRight: `1px solid ${colors.border}`,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      flexShrink: 0,
    }}>

      {/* Resources */}
      <div style={{ padding: '14px 14px 10px', borderBottom: `1px solid ${colors.border}` }}>
        <SectionLabel>Resources</SectionLabel>
        <Meter label="CPU"  value={cpu} />
        <Meter label="MEM"  value={mem} />
        <Meter label="DISK" value={disk} />
        <div style={{ fontFamily: font.mono, fontSize: 8, color: colors.muted, letterSpacing: 1, marginTop: 8 }}>
          PROC <span style={{ color: colors.text, marginLeft: 8 }}>{proc}</span>
        </div>
      </div>

      {/* Event summary */}
      <div style={{ padding: '14px 14px 10px', borderBottom: `1px solid ${colors.border}` }}>
        <SectionLabel>Events</SectionLabel>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <BigStat label="TOTAL"      value={stats?.total_events}        color={colors.green} />
          <BigStat label="CRITICAL"   value={stats?.critical_unresolved} color={colors.red} />
          <BigStat label="UNRESOLVED" value={stats?.unresolved}          color={colors.orange} />
          <BigStat label="24H"        value={stats?.last_24h}            color={colors.cyan} />
        </div>
      </div>

      {/* Actions */}
      <div style={{ padding: '14px 14px 10px' }}>
        <SectionLabel>Actions</SectionLabel>
        <ActionBtn primary onClick={onGenerateReport}>Generate Report</ActionBtn>
        <ActionBtn onClick={onFilterCritical}>Critical Only</ActionBtn>
        <ActionBtn onClick={onFilterAll}>All Events</ActionBtn>
      </div>
    </div>
  );
}