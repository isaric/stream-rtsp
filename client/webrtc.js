let config;

async function log(...msg) {
  if (config?.client?.debug) {
    const dt = new Date();
    const ts = `${dt.getHours().toString().padStart(2, '0')}:${dt.getMinutes().toString().padStart(2, '0')}:${dt.getSeconds().toString().padStart(2, '0')}.${dt.getMilliseconds().toString().padStart(3, '0')}`;
    // eslint-disable-next-line no-console
    console.log(ts, 'webrtc', ...msg);
  }
}

async function getConfig() {
  const res = await fetch('/config.json');
  const json = await res.json();
  return json;
}

async function webRTC(suuid = null, elementName = null) {
  if (!config) config = await getConfig();
  log('stream:', suuid, 'element:', elementName)
  log('client starting');
  log(`server: http://${config.streamServer}${config.server.encoderPort} stream: ${suuid}`);
  const stream = new MediaStream();
  const connection = new RTCPeerConnection();
  connection.oniceconnectionstatechange = () => log('connection', connection.iceConnectionState);
  connection.onnegotiationneeded = async () => {
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    const res = await fetch(`http://${config.streamServer}${config.server.encoderPort}/stream/receiver/${suuid}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: new URLSearchParams({
        suuid: `${suuid}`,
        data: `${btoa(connection.localDescription?.sdp || '')}`,
      }),
    });
    const data = (res && res.ok) ? await res.text() : '';
    if (data.length === 0) {
      log('cannot connect:', `http://${config.streamServer}${config.server.encoderPort}`);
    } else {
      connection.setRemoteDescription(new RTCSessionDescription({
        type: 'answer',
        sdp: atob(data),
      }));
      log('negotiation start:', offer);
    }
  };
  connection.ontrack = (event) => {
    stream.addTrack(event.track);
    const video = (typeof elementName === 'string') ? document.getElementById(elementName) : elementName;
    // @ts-ignore
    if (video instanceof HTMLVideoElement) video.srcObject = stream;
    else log('element is not a video element:', elementName);
    video.onloadeddata = async () => log('resolution:', video.videoWidth, video.videoHeight);
    log('received track:', event.track, event.track.getSettings());
  };

  const res = await fetch(`http://${config.streamServer}${config.server.encoderPort}/stream/codec/${suuid}`);
  let streams = [];
  try {
    streams = res && res.ok ? await res.json() : [];
  } catch { /**/ }
  if (streams.length === 0) {
    log('received no streams');
    return;
  }
  log('received streams:', streams);
  for (const s of streams) {
    connection.addTransceiver(s.Type, { direction: 'sendrecv' });
  }

  const channel = connection.createDataChannel(suuid, { maxRetransmits: 10 });
  channel.onmessage = (e) => log('channel message:', channel.label, 'payload', e.data);
  channel.onerror = (e) => log('channel error:', channel.label, 'payload', e);
  channel.onclose = () => log('channel close');
  channel.onopen = () => {
    log('channel open');
    setInterval(() => channel.send('ping'), 1000); // send ping becouse PION doesn't handle RTCSessionDescription.close()
  };
}

async function main() {
    config = await getConfig();
    const videos = document.getElementById('videos')
    let count = 0;
    for (stream in config.streams) {
      count++;
      const videoId = 'video-' + stream;
      const videoElem = document.createElement('video');
      videoElem.setAttribute('id', videoId);
      videoElem.setAttribute('width', '50%');
      videoElem.setAttribute('autoplay', "")
      videoElem.setAttribute('controls', "")
      videos.appendChild(videoElem);
      webRTC(stream, videoId);
    }
}

window.onload = () => main();

window.setTimeout( function() {
  Object.values(document.getElementsByTagName("video")).forEach((video) => {
    video.play();
  })
}, 5000);

