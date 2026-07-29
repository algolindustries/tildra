// The CSPRNG polyfill must be installed before anything that generates a key
// is imported. React Native has no crypto.getRandomValues of its own, and
// @noble reads it at call time — so this import has to come first, and it has
// to come before App.
import 'react-native-get-random-values';

import { registerRootComponent } from 'expo';

import App from './App';

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
