import React from 'react';

interface GlassCardProps {
  className?: string;
  children: React.ReactNode;
}

const GlassCard: React.FC<GlassCardProps> = ({ className = '', children }) => {
  return (
    <div className={`glass-panel tech-border rounded-2xl ${className}`.trim()}>
      {children}
    </div>
  );
};

export default GlassCard;
