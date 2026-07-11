import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { colors, font } from '../lib/tokens';
import { sendChatMessage, analyzeEvent, generateReport } from '../hooks/useApi';

function TypingDots() {
  return (
    <div style={{ display: 'flex', gap: 4, padding: '2px 0', alignItems: 'center' }}>
      {[0, 1, 2].map(i => (
        <motion.div
          key={i}
          animate={{ opacity: [0.2, 1, 0.2], scale: [0.8, 1, 0.8] }}
          transition={{ repeat: Infinity, duration: 1.1, delay: i * 0.18 }}
          style={{ width: 4, height: 4, borderRadius: '50%', background: colors.green }}
        />
      ))}
    </div>
  );
}

function Message({ msg }) {
  const isUser = msg.role === 'user';
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 3 }}
    >
      <div style={{
        fontFamily: font.mono,
        fontSize: 8,
        letterSpacing: 2,
        color: isUser ? colors.cyan : colors.green,
        textAlign: isUser ? 'right' : 'left',
      }}>
        {isUser ? 'OPERATOR' : 'ANALYST'}
      </div>
      <div style={{
        fontSize: 11,
        fontFamily: font.body,
        lineHeight: 1.65,
        padding: '8px 10px',
        borderRadius: 3,
        background: isUser ? `${colors.cyan}08` : colors.bg3,
        border: `1px solid ${isUser ? `${colors.cyan}20` : colors.border}`,
        borderLeft: isUser ? undefined : `2px solid ${colors.green}`,
        color: colors.text,
        alignSelf: isUser ? 'flex-end' : 'flex-start',
        maxWidth: '92%',
        whiteSpace: 'pre-wrap',
      }}>
        {msg.content}
      </div>
    </motion.div>
  );
}

export default function Analyst({ pendingEvent, onPendingClear }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'System online. Select an event to analyze, or ask about your current threat posture.' }
  ]);
  const [history, setHistory] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Auto-analyze event when selected
  useEffect(() => {
    if (!pendingEvent) return;
    handleAnalyze(pendingEvent);
    onPendingClear();
  }, [pendingEvent]);

  async function handleAnalyze(event) {
    const userMsg = `Analyze event #${event.id}: ${event.title}`;
    appendMsg('user', userMsg);
    setLoading(true);
    try {
      const d = await analyzeEvent(event.id);
      const a = d.analysis || {};
      const text = [
        `Event #${event.id} — ${(a.threat_type || 'unknown').replace(/_/g,' ')}`,
        `Confidence: ${a.confidence || 0}%   |   Level: ${(a.threat_level || '?').toUpperCase()}`,
        `False Positive Risk: ${(a.false_positive_likelihood || '?').toUpperCase()}`,
        '',
        a.summary || '',
        '',
        `Immediate action: ${a.immediate_action || 'Investigate manually'}`,
      ].join('\n');
      appendMsg('assistant', text);
    } catch (e) {
      appendMsg('assistant', 'Analysis request failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleGenReport() {
    appendMsg('user', 'Generate an incident report from current events.');
    setLoading(true);
    try {
      const d = await generateReport();
      const r = d.report || {};
      const text = [
        `Incident Report #${d.report_id}`,
        r.title || '',
        `Severity: ${(r.severity || '?').toUpperCase()}`,
        '',
        r.threat_summary || '',
        '',
        `Attack Vector: ${r.attack_vector || 'Unknown'}`,
        '',
        'Remediation:',
        (r.remediation_steps || '').slice(0, 400),
      ].join('\n');
      appendMsg('assistant', text);
    } catch (e) {
      appendMsg('assistant', 'Report generation failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleSend() {
    const text = input.trim();
    if (!text || loading) return;
    setInput('');
    const newHistory = [...history, { role: 'user', content: text }];
    setHistory(newHistory);
    appendMsg('user', text);
    setLoading(true);
    try {
      const d = await sendChatMessage(newHistory);
      const reply = d.response || 'No response.';
      setHistory(h => [...h, { role: 'assistant', content: reply }]);
      appendMsg('assistant', reply);
    } catch (e) {
      appendMsg('assistant', 'Connection failed.');
    } finally {
      setLoading(false);
    }
  }

  function appendMsg(role, content) {
    setMessages(m => [...m, { role, content }]);
  }

  return (
    <div style={{
      width: 280,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      borderLeft: `1px solid ${colors.border}`,
      flexShrink: 0,
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
        <span style={{ fontFamily: font.mono, fontSize: 9, color: colors.muted, letterSpacing: 3 }}>AI ANALYST</span>
        <span style={{ marginLeft: 'auto', fontFamily: font.mono, fontSize: 7, color: colors.dim, letterSpacing: 1 }}>
          GROQ / LLAMA-3.1
        </span>
      </div>

      {/* Quick action */}
      <motion.button
        whileTap={{ scale: 0.98 }}
        onClick={handleGenReport}
        style={{
          margin: 10,
          padding: '7px 10px',
          background: colors.greenGlow,
          border: `1px solid ${colors.green}40`,
          color: colors.green,
          fontFamily: font.mono,
          fontSize: 8,
          letterSpacing: 2,
          borderRadius: 2,
          cursor: 'pointer',
          textAlign: 'left',
          flexShrink: 0,
        }}
      >
        GENERATE INCIDENT REPORT
      </motion.button>

      {/* Messages */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '4px 12px 12px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      }}>
        <AnimatePresence initial={false}>
          {messages.map((m, i) => <Message key={i} msg={m} />)}
        </AnimatePresence>

        {loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            style={{ display: 'flex', flexDirection: 'column', gap: 3 }}
          >
            <div style={{ fontFamily: font.mono, fontSize: 8, letterSpacing: 2, color: colors.green }}>
              ANALYST
            </div>
            <div style={{
              padding: '8px 10px',
              background: colors.bg3,
              border: `1px solid ${colors.border}`,
              borderLeft: `2px solid ${colors.green}`,
              borderRadius: 3,
            }}>
              <TypingDots />
            </div>
          </motion.div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '10px 12px',
        borderTop: `1px solid ${colors.border}`,
        background: colors.bg2,
        display: 'flex',
        gap: 6,
        flexShrink: 0,
      }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder="Enter query..."
          style={{
            flex: 1,
            background: colors.bg3,
            border: `1px solid ${colors.border2}`,
            color: colors.text,
            padding: '7px 10px',
            fontFamily: font.mono,
            fontSize: 10,
            borderRadius: 2,
            outline: 'none',
          }}
          onFocus={e => e.target.style.borderColor = colors.green}
          onBlur={e => e.target.style.borderColor = colors.border2}
        />
        <motion.button
          whileTap={{ scale: 0.96 }}
          onClick={handleSend}
          disabled={loading}
          style={{
            padding: '7px 12px',
            background: loading ? colors.dim : colors.bg3,
            border: `1px solid ${loading ? colors.dim : colors.border2}`,
            color: loading ? colors.dim : colors.green,
            fontFamily: font.mono,
            fontSize: 9,
            letterSpacing: 2,
            borderRadius: 2,
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          SEND
        </motion.button>
      </div>
    </div>
  );
}