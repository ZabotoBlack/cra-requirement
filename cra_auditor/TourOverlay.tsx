import React, { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { TOUR_STEPS, TourPlacement, useTour } from './TourContext';
import { useLanguage } from './LanguageContext';

interface Rectangle {
  top: number;
  left: number;
  width: number;
  height: number;
}

const TOOLTIP_WIDTH = 340;
const TOOLTIP_MARGIN = 16;
const SPOTLIGHT_PADDING = 10;

const clamp = (value: number, minValue: number, maxValue: number): number => {
  return Math.min(Math.max(value, minValue), maxValue);
};

const interpolate = (template: string, values: Record<string, string | number>): string => {
  return template.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key] ?? ''));
};

const fallbackRect = (): Rectangle => {
  const top = window.innerHeight * 0.32;
  const left = window.innerWidth * 0.25;
  const width = window.innerWidth * 0.5;
  const height = 88;

  return { top, left, width, height };
};

const resolveTooltipPosition = (targetRect: Rectangle, placement: TourPlacement): React.CSSProperties => {
  const tooltipHeightGuess = 220;
  const maxLeft = Math.max(window.innerWidth - TOOLTIP_WIDTH - TOOLTIP_MARGIN, TOOLTIP_MARGIN);

  if (placement === 'top') {
    const left = clamp(targetRect.left + targetRect.width / 2 - TOOLTIP_WIDTH / 2, TOOLTIP_MARGIN, maxLeft);
    const top = clamp(targetRect.top - tooltipHeightGuess - TOOLTIP_MARGIN, TOOLTIP_MARGIN, window.innerHeight - tooltipHeightGuess - TOOLTIP_MARGIN);
    return { left, top };
  }

  if (placement === 'left') {
    const left = clamp(targetRect.left - TOOLTIP_WIDTH - TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxLeft);
    const top = clamp(targetRect.top + targetRect.height / 2 - tooltipHeightGuess / 2, TOOLTIP_MARGIN, window.innerHeight - tooltipHeightGuess - TOOLTIP_MARGIN);
    return { left, top };
  }

  if (placement === 'right') {
    const left = clamp(targetRect.left + targetRect.width + TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxLeft);
    const top = clamp(targetRect.top + targetRect.height / 2 - tooltipHeightGuess / 2, TOOLTIP_MARGIN, window.innerHeight - tooltipHeightGuess - TOOLTIP_MARGIN);
    return { left, top };
  }

  const left = clamp(targetRect.left + targetRect.width / 2 - TOOLTIP_WIDTH / 2, TOOLTIP_MARGIN, maxLeft);
  const top = clamp(targetRect.top + targetRect.height + TOOLTIP_MARGIN, TOOLTIP_MARGIN, window.innerHeight - tooltipHeightGuess - TOOLTIP_MARGIN);
  return { left, top };
};

const TourOverlay: React.FC = () => {
  const { t } = useLanguage();
  const { isTourActive, currentStep, nextStep, prevStep, endTour } = useTour();
  const [targetRect, setTargetRect] = useState<Rectangle | null>(null);

  const currentTourStep = TOUR_STEPS[currentStep];

  useEffect(() => {
    if (!isTourActive || !currentTourStep) {
      setTargetRect(null);
      return;
    }

    const updateTargetPosition = (shouldScroll = false) => {
      const element = document.querySelector(currentTourStep.targetSelector) as HTMLElement | null;

      if (!element) {
        setTargetRect(fallbackRect());
        return;
      }

      if (shouldScroll) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
      }
      const rect = element.getBoundingClientRect();
      setTargetRect({
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height
      });
    };

    updateTargetPosition(true);

    const animationFrameId = window.requestAnimationFrame(() => updateTargetPosition(false));
    const handleLayoutChange = () => updateTargetPosition(false);

    window.addEventListener('resize', handleLayoutChange);
    window.addEventListener('scroll', handleLayoutChange, true);

    return () => {
      window.cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleLayoutChange);
      window.removeEventListener('scroll', handleLayoutChange, true);
    };
  }, [isTourActive, currentTourStep]);

  useEffect(() => {
    if (!isTourActive) {
      return;
    }

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        endTour();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [isTourActive, endTour]);

  const progressText = useMemo(() => {
    return interpolate(t('tour.progress'), { current: currentStep + 1, total: TOUR_STEPS.length });
  }, [t, currentStep]);

  if (!isTourActive || !currentTourStep || typeof document === 'undefined' || !targetRect) {
    return null;
  }

  const spotlightStyle: React.CSSProperties = {
    top: Math.max(targetRect.top - SPOTLIGHT_PADDING, TOOLTIP_MARGIN),
    left: Math.max(targetRect.left - SPOTLIGHT_PADDING, TOOLTIP_MARGIN),
    width: Math.min(targetRect.width + SPOTLIGHT_PADDING * 2, window.innerWidth - TOOLTIP_MARGIN * 2),
    height: Math.min(targetRect.height + SPOTLIGHT_PADDING * 2, window.innerHeight - TOOLTIP_MARGIN * 2)
  };

  const tooltipStyle = resolveTooltipPosition(targetRect, currentTourStep.placement);

  return createPortal(
    <div className="tour-overlay" role="presentation">
      <div className="tour-spotlight" style={spotlightStyle} />
      <div className={`tour-tooltip tour-tooltip-${currentTourStep.placement}`} style={tooltipStyle} role="dialog" aria-live="polite">
        <div className="tour-tooltip-arrow" />
        <div className="tour-progress">{progressText}</div>
        <h3>{t(currentTourStep.titleKey)}</h3>
        <p>{t(currentTourStep.descriptionKey)}</p>
        <div className="tour-tooltip-actions">
          <button type="button" onClick={prevStep} disabled={currentStep === 0}>{t('tour.btn.back')}</button>
          <button type="button" onClick={nextStep}>{t('tour.btn.next')}</button>
          <button type="button" onClick={endTour}>{t('tour.btn.endTour')}</button>
        </div>
      </div>
    </div>,
    document.body
  );
};

export default TourOverlay;
