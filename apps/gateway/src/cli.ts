import { initializeGateway,loadGatewayDeployment } from '../../../packages/gateway/src/deployment.js';
import { startGateway,checkGatewayHealth } from '../../../packages/gateway/src/service.js';

async function main() {
  process.umask(0o077);
  const args=process.argv.slice(2);let configPath=process.env.NAS_GATEWAY_CONFIG,issuer:string|undefined;
  const callbacks:string[]=[];let initialize=false,health=false;
  for(let i=0;i<args.length;i++){
    const arg=args[i];
    if(arg==='--init'){if(initialize)throw new Error('Duplicate init');initialize=true;}
    else if(arg==='--healthcheck'){if(health)throw new Error('Duplicate healthcheck');health=true;}
    else if(['--config','--issuer','--callback'].includes(arg??'')){
      const value=args[++i];if(!value||value.startsWith('--'))throw new Error('Missing option value');
      if(arg==='--config')configPath=value;
      else if(arg==='--issuer'){if(issuer)throw new Error('Duplicate issuer');issuer=value;}
      else callbacks.push(value);
    }else throw new Error('Unknown option');
  }
  if(!configPath||initialize&&health||!initialize&&(issuer||callbacks.length))throw new Error('Invalid command');
  if(initialize){
    if(!issuer||!callbacks.length)throw new Error('Explicit issuer and callbacks required');
    await initializeGateway(configPath,issuer,callbacks);console.error('GATEWAY_INITIALIZED: configure TLS files before starting; keep state and auth.key together.');return;
  }
  const config=await loadGatewayDeployment(configPath);
  if(health){await checkGatewayHealth(config);return;}
  const runtime=await startGateway(config);console.error('GATEWAY_READY');
  let stopping=false;
  const stop=()=>{if(stopping)return;stopping=true;void runtime.close().then(()=>{console.error('GATEWAY_STOPPED');},()=>{console.error('GATEWAY_SHUTDOWN_FAILED');process.exitCode=1;});};
  runtime.server.on('error',()=>{console.error('GATEWAY_LISTENER_FAILED');process.exitCode=1;stop();});
  for(const signal of ['SIGTERM','SIGINT'] as const)process.once(signal,stop);
}
main().catch(()=>{console.error('GATEWAY_STARTUP_FAILED: check private configuration, TLS files, state/key consistency and whether another instance is running.');process.exitCode=1;});
