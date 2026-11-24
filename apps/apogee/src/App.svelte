<script lang="ts">
  import { corruptStoreRecovery, failureCode, startup } from './ipc';

  let pending = startup();

  function retryStartup() {
    pending = startup();
  }
</script>

<main>
  <h1>Apogee</h1>
  {#await pending}
    <p>Starting.</p>
  {:then info}
    <p>Version {info.version}, default region {info.defaults.launch.region}.</p>
  {:catch error}
    {@const recovery = corruptStoreRecovery(error)}
    {#if recovery}
      <section aria-labelledby="corrupt-store-title">
        <h2 id="corrupt-store-title">Stored settings need attention</h2>
        <p>Apogee could not read {recovery.path}.</p>
        <p>The original was kept and a recovery copy is at {recovery.backup}.</p>
        <p>Code: {recovery.code}</p>
        <button type="button" onclick={retryStartup}>Try again</button>
      </section>
    {:else}
      <p>Startup failed with {failureCode(error)}.</p>
    {/if}
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
