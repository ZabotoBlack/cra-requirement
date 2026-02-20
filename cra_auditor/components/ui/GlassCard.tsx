import React from 'react';

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
  children: React.ReactNode;
}

const GlassCard: React.FC<GlassCardProps> = ({ className = '', children, ...rest }) => {
  return (
    <div className={`glass-panel tech-border rounded-2xl ${className}`.trim()} {...rest}>
      {children}
    </div>
  );
};

export default GlassCard;
