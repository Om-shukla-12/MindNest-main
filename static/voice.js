const micBtn = document.getElementById('micBtn');
const entry = document.getElementById('entry');
const languageSelect = document.getElementById('language');
const journalForm = document.getElementById('journalForm');

let isRecording = false;
let micStream = null;

const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
const recognition = new SpeechRecognition();

recognition.continuous = true;
recognition.interimResults = false;

micBtn.addEventListener('click', () => {
  if (isRecording) {
    recognition.stop();
    micBtn.classList.remove('active');
    isRecording = false;
    if (micStream) {
      micStream.getTracks().forEach(track => track.stop());
    }
  } else {
    navigator.mediaDevices.getUserMedia({
      audio: {
        noiseSuppression: true,
        echoCancellation: true,
        autoGainControl: true
      }
    }).then((stream) => {
      micStream = stream;
      recognition.lang = languageSelect?.value || 'en-IN';
      recognition.start();
      micBtn.classList.add('active');
      isRecording = true;
    }).catch((err) => {
      alert('Microphone access denied: ' + err.message);
      console.error(err);
    });
  }
});

// Combine all results properly
recognition.onresult = (event) => {
  let finalTranscript = '';
  for (let i = event.resultIndex; i < event.results.length; ++i) {
    if (event.results[i].isFinal) {
      finalTranscript += event.results[i][0].transcript.trim() + ' ';
    }
  }
  if (finalTranscript) {
    entry.value += (entry.value ? ' ' : '') + finalTranscript.trim();
  }
};

recognition.onerror = (event) => {
  console.error('Speech recognition error:', event.error);
  micBtn.classList.remove('active');
  isRecording = false;
  if (micStream) {
    micStream.getTracks().forEach(track => track.stop());
  }

  if (event.error === 'no-speech' || event.error === 'aborted') {
    // Optionally restart if it was a minor error
    if (isRecording) {
      recognition.start();
    }
  } else {
    alert('Voice input error: ' + event.error);
  }
};

recognition.onend = () => {
  if (isRecording) {
    // Auto-restart unless manually stopped
    recognition.start();
  } else {
    micBtn.classList.remove('active');
  }
};

// Prevent empty form submission
journalForm.addEventListener('submit', (e) => {
  if (!entry.value.trim()) {
    e.preventDefault();
    alert('Please type or speak something before submitting your journal entry.');
  }
});
