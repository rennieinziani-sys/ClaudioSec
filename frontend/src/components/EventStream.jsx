import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { colors, font, SEV_COLOR, SEV_BG, SEV_BORDER } from '../lib/tokens';

const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function FilterBtn({ label, active, onClick }) {
  const sev = label.toLowerCase();
  const activeColor = SEV_COLOR[sev] || colors.green;
  return (
    <motion.button
      whileTap={{ scale: 0.95 }}
      onClick={onClick}
      style={{
        fontFamily: font.mono,
        fontSize: 8,
        letterSpacing: 2,
        padding: '3px 9px',
        borderRadius: 2,
        border: `1px solid ${active ? (SEV_BORDER[sev] || 'rgba(61,220,132,0.3)') : colors.border2}`,
        background: active ? (SEV_BG[sev] || colors.greenGlow) : 'transparent',
        color: active ? (activeColor) : colors.muted,
        cursor: 'pointer',
        transition: 'all 0.1s',
      }}
    >
      {label}
    </motion.button>
  );
}

function SevTag({ severity }) {
  return (
    <div style={{
      fontFamily: font.mono,
      fontSize: 8,
      letterSpacing: 1,
      padding: '2px 6px',
      borderRadius: 2,
      border: `1px solid ${SEV_BORDER[severity] || colors.border}`,
      background: SEV_BG[severity] || 'transparent',
      color: SEV_COLOR[severity] || colors.text,
      whiteSpace: 'nowrap',
      textAlign: 'center',
    }}>
      {(severity || '').toUpperCase()}
    </div>
  );
}

function EventRow({ event, onClick, isNew }) {
  const [hovered, setHovered] = useState(false);
  const sev = event.severity || 'low';

  return (
    <motion.div
      initial={isNew ? { opacity: 0, x: -12, background: `${SEV_COLOR[sev]}15` } : { opacity: 1 }}
      animate={{ opacity: 1, x: 0, background: hovered ? `${colors.bg4}` : colors.bg3 }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.25 }}
      onHoverStart={() => setHovered(true)}
      onHoverEnd={() => setHovered(false)}
      onClick={() => onClick(event)}
      style={{
        display: 'grid',
        gridTemplateColumns: '2px 80px 106px 1fr 68px',
        alignItems: 'center',
        gap: 10,
        padding: '8px 14px',
        borderBottom: `1px solid ${colors.border}`,
        cursor: 'pointer',
      }}
    >
      {/* Severity bar */}
      <motion.div
        animate={{ opacity: sev === 'critical' ? [1, 0.3, 1] : 1 }}
        transition={{ repeat: sev === 'critical' ? Infinity : 0, duration: 1 }}
        style={{
          width: 2, height: 26, borderRadius: 1,
          background: SEV_COLOR[sev] || colors.green,
          boxShadow: `0 0 6px ${SEV_COLOR[sev]}`,
        }}
      />
      <SevTag severity={sev} />
      <div style={{
        fontFamily: font.mono, fontSize: 8,
        color: colors.cyan, letterSpacing: 0.5,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
      }}>
        {(event.event_type || '').replace(/_/g, ' ')}
      </div>
      <div style={{
        fontSize: 12, fontWeight: 500,
        fontFamily: font.body,
        color: hovered ? colors.text : '#b0b0b0',
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        transition: 'color 0.1s',
      }}>
        {event.title}
      </div>
      <div style={{
        fontFamily: font.mono, fontSize: 8,
        color: colors.muted, textAlign: 'right',
      }}>
        {(event.timestamp || '').slice(11, 19)}
      </div>
    </motion.div>
  );
}

export default function EventStream({ events, loading, filter, onFilterChange, onSelectEvent }) {
  const [newIds] = useState(new Set());

  return (
    <div style={{
      flex: 1,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      borderRight: `1px solid ${colors.border}`,
    }}>
      {/* Header */}
      <div style={{
        height: 36,
        background: colors.bg2,
        borderBottom: `1px solid ${colors.border}`,
        display: 'flex',
        alignItems: 'center',
        padding: '0 14px',
        gap: 8,
        flexShrink: 0,
      }}>
        <span style={{ fontFamily: font.mono, fontSize: 9, color: colors.muted, letterSpacing: 3 }}>
          LIVE STREAM
        </span>
        <motion.div
          animate={{ opacity: [1, 0.3, 1] }}
          transition={{ repeat: Infinity, duration: 1.5 }}
          style={{ width: 4, height: 4, borderRadius: '50%', background: colors.green }}
        />
        <span style={{ marginLeft: 'auto', fontFamily: font.mono, fontSize: 8, color: colors.muted }}>
          {events.length} events
        </span>
      </div>

      {/* Filter bar */}
      <div style={{
        height: 34,
        background: colors.bg2,
        borderBottom: `1px solid ${colors.border}`,
        display: 'flex',
        alignItems: 'center',
        padding: '0 14px',
        gap: 6,
        flexShrink: 0,
      }}>
        {FILTERS.map(f => (
          <FilterBtn
            key={f}
            label={f}
            active={filter === f.toLowerCase()}
            onClick={() => onFilterChange(f.toLowerCase())}
          />
        ))}
      </div>

      {/* Events */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {loading ? (
          <div style={{
            padding: 48, textAlign: 'center',
            fontFamily: font.mono, fontSize: 10,
            color: colors.dim, letterSpacing: 2,
          }}>
            <motion.div animate={{ opacity: [0.3, 1, 0.3] }} transition={{ repeat: Infinity, duration: 1.5 }}>
              CONNECTING...
            </motion.div>
          </div>
        ) : events.length === 0 ? (
          <div style={{
            padding: 48, textAlign: 'center',
            fontFamily: font.mono, fontSize: 10,
            color: colors.dim, letterSpacing: 2,
          }}>
            NO EVENTS MATCHING FILTER
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {events.map(ev => (
              <EventRow
                key={ev.id}
                event={ev}
                isNew={newIds.has(ev.id)}
                onClick={onSelectEvent}
              />
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}