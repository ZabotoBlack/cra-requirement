import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { TranslationKey } from './translations';
import { UserMode, ViewState } from './types';

export type TourPlacement = 'top' | 'bottom' | 'left' | 'right';

export interface TourStep {
  targetSelector: string;
  titleKey: TranslationKey;
  descriptionKey: TranslationKey;
  placement: TourPlacement;
  spotlightOffsetX?: number;
  spotlightOffsetY?: number;
  spotlightWidthAdjust?: number;
  spotlightHeightAdjust?: number;
  viewRequirement?: ViewState;
  requiresSidebarExpanded?: boolean;
  opensSettings?: boolean;
  requiredMode?: UserMode;
}

/** Ordered, translated tour steps used by the onboarding overlay. */
export const TOUR_STEPS: TourStep[] = [
  {
    targetSelector: '[data-tour-id="brand-icon"]',
    titleKey: 'tour.step.1.title',
    descriptionKey: 'tour.step.1.description',
    placement: 'right',
    spotlightOffsetX: -12,
    requiresSidebarExpanded: true
  },
  {
    targetSelector: '[data-tour-id="sidebar-nav"]',
    titleKey: 'tour.step.2.title',
    descriptionKey: 'tour.step.2.description',
    placement: 'right',
    spotlightOffsetX: -12,
    requiresSidebarExpanded: true,
    requiredMode: 'intermediate'
  },
  {
    targetSelector: '[data-tour-id="ui-mode-selector"]',
    titleKey: 'tour.step.3.title',
    descriptionKey: 'tour.step.3.description',
    placement: 'right',
    spotlightOffsetX: -12,
    requiresSidebarExpanded: true
  },
  {
    targetSelector: '[data-tour-id="language-selector"]',
    titleKey: 'tour.step.4.title',
    descriptionKey: 'tour.step.4.description',
    placement: 'right',
    spotlightOffsetX: -12,
    requiresSidebarExpanded: true
  },
  {
    targetSelector: '[data-tour-id="theme-toggle"]',
    titleKey: 'tour.step.5.title',
    descriptionKey: 'tour.step.5.description',
    placement: 'right',
    spotlightOffsetX: -12,
    requiresSidebarExpanded: true
  },
  {
    targetSelector: '[data-tour-id="subnet-input"]',
    titleKey: 'tour.step.6.title',
    descriptionKey: 'tour.step.6.description',
    placement: 'bottom'
  },
  {
    targetSelector: '[data-tour-id="settings-button"]',
    titleKey: 'tour.step.7.title',
    descriptionKey: 'tour.step.7.description',
    placement: 'bottom'
  },
  {
    targetSelector: '[data-tour-id="settings-scan-depth"], [data-tour-id="settings-button"]',
    titleKey: 'tour.step.8.title',
    descriptionKey: 'tour.step.8.description',
    placement: 'bottom',
    spotlightOffsetY: 10,
    spotlightWidthAdjust: -24,
    spotlightHeightAdjust: 16,
    opensSettings: true
  },
  {
    targetSelector: '[data-tour-id="settings-vendor-detection"], [data-tour-id="settings-button"]',
    titleKey: 'tour.step.9.title',
    descriptionKey: 'tour.step.9.description',
    placement: 'bottom',
    opensSettings: true
  },
  {
    targetSelector: '[data-tour-id="settings-active-probing-label"], [data-tour-id="settings-active-probing"], [data-tour-id="settings-button"]',
    titleKey: 'tour.step.10.title',
    descriptionKey: 'tour.step.10.description',
    placement: 'bottom',
    opensSettings: true,
    requiredMode: 'expert'
  },
  {
    targetSelector: '[data-tour-id="start-scan-button"]',
    titleKey: 'tour.step.11.title',
    descriptionKey: 'tour.step.11.description',
    placement: 'bottom'
  },
  {
    targetSelector: '[data-tour-id="status-badges"]',
    titleKey: 'tour.step.12.title',
    descriptionKey: 'tour.step.12.description',
    placement: 'bottom'
  },
  {
    targetSelector: '[data-tour-id="dashboard-area"], [data-tour-id="nav-dashboard"]',
    titleKey: 'tour.step.13.title',
    descriptionKey: 'tour.step.13.description',
    placement: 'top',
    viewRequirement: 'dashboard'
  },
  {
    targetSelector: '[data-tour-id="devices-list-panel"], [data-tour-id="nav-devices"]',
    titleKey: 'tour.step.14.title',
    descriptionKey: 'tour.step.14.description',
    placement: 'top',
    viewRequirement: 'devices',
    requiredMode: 'intermediate'
  },
  {
    targetSelector: '[data-tour-id="history-area"], [data-tour-id="nav-history"]',
    titleKey: 'tour.step.15.title',
    descriptionKey: 'tour.step.15.description',
    placement: 'top',
    viewRequirement: 'history'
  }
];

interface TourContextValue {
  isTourActive: boolean;
  currentStep: number;
  startTour: () => void;
  endTour: () => void;
  nextStep: () => void;
  prevStep: () => void;
}

const TourContext = createContext<TourContextValue | undefined>(undefined);

export const TourProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isTourActive, setIsTourActive] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);

  const startTour = useCallback(() => {
    setCurrentStep(0);
    setIsTourActive(true);
  }, []);

  const endTour = useCallback(() => {
    setIsTourActive(false);
  }, []);

  const nextStep = useCallback(() => {
    setCurrentStep((previousStep) => {
      if (previousStep >= TOUR_STEPS.length - 1) {
        setIsTourActive(false);
        return previousStep;
      }
      return previousStep + 1;
    });
  }, []);

  const prevStep = useCallback(() => {
    setCurrentStep((previousStep) => Math.max(previousStep - 1, 0));
  }, []);

  const contextValue = useMemo(() => ({
    isTourActive,
    currentStep,
    startTour,
    endTour,
    nextStep,
    prevStep
  }), [isTourActive, currentStep, startTour, endTour, nextStep, prevStep]);

  return (
    <TourContext.Provider value={contextValue}>
      {children}
    </TourContext.Provider>
  );
};

/** Typed hook wrapper around the tour context with provider guard. */
export const useTour = (): TourContextValue => {
  const context = useContext(TourContext);

  if (!context) {
    throw new Error('useTour must be used within TourProvider.');
  }

  return context;
};
