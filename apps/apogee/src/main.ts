import { mount } from 'svelte';

import App from './App.svelte';
import { renderOk } from './ipc';

requestAnimationFrame(() => {
  requestAnimationFrame(() => {
    void renderOk();
  });
});

export default mount(App, { target: document.body });
