import React from 'react';

interface TechButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'danger';
}

const variantClasses: Record<NonNullable<TechButtonProps['variant']>, string> = {
  primary: 'border-[var(--color-accent-border)] bg-[var(--color-accent-soft)] text-[var(--color-accent)] hover:bg-[color-mix(in_srgb,var(--color-accent)_28%,transparent)] hover:text-[var(--text-main)]',
  secondary: 'border-[var(--border-subtle)] bg-[var(--bg-card)] text-[var(--text-main)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-elevated)]',
  danger: 'border-[var(--badge-danger-border)] bg-[var(--badge-danger-bg)] text-[var(--badge-danger-text)] hover:bg-[color-mix(in_srgb,var(--badge-danger-bg)_72%,var(--badge-danger-text)_28%)]',
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
      className={`inline-flex items-center justify-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold tracking-wide transition-all ${variantClasses[variant]} ${disabled ? 'opacity-50 cursor-not-allowed' : 'shadow-[0_0_20px_color-mix(in_srgb,var(--color-accent)_18%,transparent)]'} ${className}`.trim()}
      {...props}
    >
      {children}
    </button>
  );
};

export default TechButton;
