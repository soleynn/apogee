<script lang="ts">
  import { startup } from './ipc';

  const pending = startup();
</script>

<main>
  <h1>Apogee</h1>
  {#await pending}
    <p>Starting.</p>
  {:then info}
    <p>Version {info.version}, default region {info.defaultRegion}.</p>
  {:catch error}
    <p>{error}</p>
  {/await}
</main>

<style>
  main {
    font-family: system-ui, sans-serif;
    padding: 2rem;
  }

  h1 {
    font-size: 1.5rem;
    margin: 0 0 0.5rem;
  }
</style>
