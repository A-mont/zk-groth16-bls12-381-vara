import {
  ApiProvider as GearApiProvider,
  AlertProvider as GearAlertProvider,
  AccountProvider as GearAccountProvider,
  ProviderProps,
} from '@gear-js/react-hooks';
import { Alert, alertStyles } from '@gear-js/vara-ui';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ComponentType } from 'react';

import { ADDRESS } from '@/consts';

function ApiProvider({ children }: ProviderProps) {
  return <GearApiProvider initialArgs={{ endpoint: ADDRESS.NODE }}>{children}</GearApiProvider>;
}

function AlertProvider({ children }: ProviderProps) {
  return (
    <GearAlertProvider template={Alert} containerClassName={alertStyles.root}>
      {children}
    </GearAlertProvider>
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { gcTime: 0, staleTime: Infinity, refetchOnWindowFocus: false, retry: false },
  },
});

function QueryProvider({ children }: ProviderProps) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

function AccountProvider({ children }: ProviderProps) {
  return <GearAccountProvider appName="ZK on Vara">{children}</GearAccountProvider>;
}

const providers = [AlertProvider, ApiProvider, AccountProvider, QueryProvider];

function withProviders(Component: ComponentType) {
  return () => providers.reduceRight((children, Provider) => <Provider>{children}</Provider>, <Component />);
}

export { withProviders };
