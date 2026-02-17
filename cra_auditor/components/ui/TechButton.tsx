import React from 'react';

interface TechButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'danger';
}

const variantClasses: Record<NonNullable<TechButtonProps['variant']>, string> = {
  primary: 'bg-cyan-500/20 text-cyan-200 border-cyan-400/40 hover:bg-cyan-400/30 hover:text-white',
  secondary: 'bg-slate-700/30 text-slate-200 border-slate-500/40 hover:bg-slate-600/40 hover:text-white',
  danger: 'bg-rose-500/20 text-rose-200 border-rose-400/40 hover:bg-rose-500/35 hover:text-white',
};

const TechButton: React.FC<TechButtonProps> = ({
  children,
  className = '',
  variant = 'secondary',
  disabled,
  ...props
}) => {
  return (
    <button
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold tracking-wide transition-all ${variantClasses[variant]} ${disabled ? 'opacity-50 cursor-not-allowed' : 'shadow-[0_0_20px_rgba(34,211,238,0.08)]'} ${className}`.trim()}
      {...props}
    >
      {children}
    </button>
  );
};

export default TechButton;
