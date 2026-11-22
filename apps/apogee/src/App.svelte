<script lang="ts">
  import { onMount } from 'svelte';

  import {
    answerCloseRequest,
    confirmRender,
    corruptStoreRecovery,
    failureCode,
    onInstanceAttention,
    onQuitDuringRun,
    renderStatus,
    startup,
  } from './ipc';

  let pending = startup();
  let renderNeedsConfirmation = false;
  let renderer = renderStatus().then((status) => {
    renderNeedsConfirmation = status.requiresConfirmation;
    return status;
  });
  let renderConfirmed = false;
  let closeRequested = false;
  let instanceHighlighted = false;

  onMount(() => {
    let stopClose: (() => void) | undefined;
    let stopAttention: (() => void) | undefined;
    void onQuitDuringRun(() => {
      closeRequested = true;
    }).then((stop) => {
      stopClose = stop;
    });
    void onInstanceAttention(() => {
      instanceHighlighted = true;
    }).then((stop) => {
      stopAttention = stop;
    });
    return () => {
      stopClose?.();
      stopAttention?.();
    };
  });

  function retryStartup() {
    pending = startup();
  }

  async function acceptRenderer() {
    await confirmRender();
    renderNeedsConfirmation = false;
    renderConfirmed = true;
  }

  async function answerClose(confirmed: boolean) {
    await answerCloseRequest(confirmed);
    if (!confirmed) closeRequested = false;
  }
</script>

<svelte:window
  onkeydown={(event) => {
    if (event.key === 'Enter' && renderNeedsConfirmation) void acceptRenderer();
  }}
/>

<main>
  {#if instanceHighlighted}
    <p role="status">Another Apogee launch highlighted this window.</p>
  {/if}
  {#await renderer}
    <p>Checking the window.</p>
  {:then status}
    {#if status.requiresConfirmation && !renderConfirmed}
      <section class="legibility" aria-labelledby="legibility-title">
        <h1 id="legibility-title">Apogee is running. Press Enter to continue.</h1>
        <dl>
          <dt>GPU</dt><dd>{status.gpu ?? 'Not detected'}</dd>
          <dt>Driver</dt><dd>{status.driver ?? 'Not detected'}</dd>
          <dt>Session</dt><dd>{status.session}</dd>
          <dt>Render tier</dt><dd>{status.tier}</dd>
        </dl>
        <button type="button" onclick={acceptRenderer}>Continue</button>
      </section>
    {:else}
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
    {/if}
  {:catch error}
    <p>Renderer check failed with {failureCode(error)}.</p>
  {/await}

  {#if closeRequested}
    <dialog class="close-confirmation" open aria-labelledby="close-title">
      <h2 id="close-title">Stop active work and close Apogee?</h2>
      <p>Closing now cancels active operations after they reach a safe boundary.</p>
      <div>
        <button type="button" onclick={() => void answerClose(false)}>Keep open</button>
        <button type="button" onclick={() => void answerClose(true)}>Stop and close</button>
      </div>
    </dialog>
  {/if}
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

  .legibility {
    outline: none;
  }

  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.5rem 1rem;
  }

  dd {
    margin: 0;
  }

  .close-confirmation {
    background: Canvas;
    border: 1px solid ButtonBorder;
    inset: 20%;
    margin: 0;
    padding: 1.5rem;
    position: fixed;
  }
</style>
