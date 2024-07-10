<script>
  import { writable } from 'svelte/store';

  // Stores
  let rawHeaders = writable('');
  let error = writable('');
  let step = writable(1);
  let analysisResult = writable({
    subject: '',
    receivedDelay: 0,
    spf: '',
    dkim: '',
    dmarc: '',
    headers: []
  });

  // Functions
  function parseHeaders(headers) {
    try {
      const parsed = headers.split('\n').map(line => {
        const [key, ...value] = line.split(':');
        if (!key || value.length === 0) {
          throw new Error(`Invalid header line: ${line}`);
        }
        return { key: key.trim(), value: value.join(':').trim() };
      }).filter(header => header.key && header.value);
      return parsed;
    } catch (err) {
      error.set(`Failed to parse headers: ${err.message}`);
      return [];
    }
  }

  function analyzeHeaders() {
    const headers = parseHeaders($rawHeaders);
    if (headers.length === 0) {
      if (!$error) {
        error.set('Failed to parse headers. Please ensure they are in the correct format.');
      }
      return;
    }

    const subject = headers.find(header => header.key.toLowerCase() === 'subject')?.value || 'N/A';
    const receivedHeaders = headers.filter(header => header.key.toLowerCase() === 'received');
    const spf = headers.find(header => header.key.toLowerCase() === 'received-spf')?.value || 'N/A';
    const dkim = headers.find(header => header.key.toLowerCase() === 'dkim-signature')?.value || 'N/A';
    const dmarc = headers.find(header => header.key.toLowerCase() === 'authentication-results')?.value || 'N/A';

    let receivedDelay = 0;
    if (receivedHeaders.length >= 2) {
      try {
        const receivedTimes = receivedHeaders.map(header => new Date(header.value.split(';').pop().trim()).getTime());
        receivedDelay = Math.floor((Math.max(...receivedTimes) - Math.min(...receivedTimes)) / 1000);
      } catch (e) {
        error.set('Error parsing dates in Received headers.');
        return;
      }
    }

    analysisResult.set({
      subject,
      receivedDelay,
      spf,
      dkim,
      dmarc,
      headers
    });

    step.set(2);
  }

  function goBack() {
    step.set(1);
    error.set('');
  }
</script>

<style>
  .app {
    font-family: Arial, sans-serif;
    margin: 20px;
  }
  .uploader, .result {
    margin-bottom: 20px;
  }
  textarea {
    width: 100%;
    height: 100px;
    margin-bottom: 10px;
    padding: 10px;
    font-size: 14px;
    border: 1px solid #ccc;
    border-radius: 5px;
  }
  button {
    padding: 10px 20px;
    background-color: #007BFF;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
  }
  button:hover {
    background-color: #0056b3;
  }
  .result-section {
    border: 1px solid #ddd;
    border-radius: 5px;
    padding: 10px;
    margin-bottom: 10px;
    background-color: #f9f9f9;
  }
  h2, h3 {
    margin-top: 0;
  }
  ul {
    list-style-type: none;
    padding: 0;
  }
  li {
    padding: 5px 0;
  }
  .error {
    color: red;
    margin-bottom: 10px;
  }
</style>

{#if $step === 1}
  <div class="app">
    <h2>Email Header Analyzer</h2>
    <div class="uploader">
      <textarea bind:value={$rawHeaders} placeholder="Paste email headers here..."></textarea>
      {#if $error}
        <div class="error">{$error}</div>
      {/if}
      <button on:click={analyzeHeaders}>Analyze Header</button>
    </div>
    <div>
      <h3>About Email Headers</h3>
      <p>This tool will make email headers human readable by parsing them according to RFC 822. Email headers are present on every email you receive via the Internet and can provide valuable diagnostic information like hop delays, authentication results, and more.</p>
    </div>
  </div>
{:else if $step === 2}
  <div class="app">
    <h2>Header Analyzed</h2>
    <div class="result-section">
      <h3>Delivery Information</h3>
      <p>Email Subject: {$analysisResult.subject}</p>
    </div>
    <div class="result-section">
      <h3>Relay Information</h3>
      <p>Received Delay: {$analysisResult.receivedDelay} seconds</p>
    </div>
    <div class="result-section">
      <h3>SPF, DKIM, and DMARC Information</h3>
      <ul>
        <li><strong>SPF:</strong> {$analysisResult.spf}</li>
        <li><strong>DKIM:</strong> {$analysisResult.dkim}</li>
        <li><strong>DMARC:</strong> {$analysisResult.dmarc}</li>
      </ul>
    </div>
    <div class="result-section">
      <h3>Headers Found</h3>
      <ul>
        {#each $analysisResult.headers as header}
          <li><strong>{header.key}:</strong> {header.value}</li>
        {/each}
      </ul>
    </div>
    <div class="result-section">
      <h3>Raw Headers</h3>
      <textarea readonly>{$rawHeaders}</textarea>
    </div>
    <button on:click={goBack}>Go Back</button>
  </div>
{/if}