/* ===== x8bitranjit security guides — SPA router + markdown renderer ===== */

/* ---- Site map. Live kits: Recon, JWT, XSS, CSRF, WebSocket, IDOR, Race Condition, GraphQL. ---- */
const DOCS = {
  'about':        { doc:'content/about.md',        title:'About',                    chips:[] },

  'recon/guide':    { doc:'content/recon-guide.md',     title:'Recon — Web Recon Guide',    chips:['Web','Attack surface'] },
  'recon/arsenal':  { doc:'content/recon-arsenal.md',   title:'Recon — Arsenal',            chips:['Web','Copy-paste'] },
  'recon/checklist':{ doc:'content/recon-checklist.md', title:'Recon — Checklist',          chips:['Web','Per-target'] },
  'recon/poc':      { doc:'content/recon-poc.md',       title:'Recon — Scripts',            chips:['Web','Runnable scripts'] },
  'recon/qa':       { doc:'content/recon-qa.md',        title:'Recon — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'jwt/guide':    { doc:'content/jwt-guide.md',     title:'JWT — Testing Guide',      chips:['Web','Critical: ATO / Auth-bypass'] },
  'jwt/arsenal':  { doc:'content/jwt-arsenal.md',   title:'JWT — Attack Arsenal',     chips:['Web','Copy-paste'] },
  'jwt/checklist':{ doc:'content/jwt-checklist.md', title:'JWT — Testing Checklist',  chips:['Web','Per-token'] },
  'jwt/poc':      { doc:'content/jwt-poc.md',       title:'JWT — PoC Scripts',        chips:['Web','Runnable scripts'] },
  'jwt/qa':       { doc:'content/jwt-qa.md',        title:'JWT — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'xss/guide':    { doc:'content/xss-guide.md',     title:'XSS — Testing Guide',      chips:['Web','Critical: ATO / session theft'] },
  'xss/arsenal':  { doc:'content/xss-arsenal.md',   title:'XSS — Payload Arsenal',    chips:['Web','Copy-paste'] },
  'xss/checklist':{ doc:'content/xss-checklist.md', title:'XSS — Testing Checklist',  chips:['Web','Per-target'] },
  'xss/poc':      { doc:'content/xss-poc.md',       title:'XSS — PoC Scripts',        chips:['Web','Runnable scripts'] },
  'xss/qa':       { doc:'content/xss-qa.md',        title:'XSS — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'csrf/guide':    { doc:'content/csrf-guide.md',     title:'CSRF — Testing Guide',     chips:['Web','High: state-change / ATO'] },
  'csrf/arsenal':  { doc:'content/csrf-arsenal.md',   title:'CSRF — Attack Arsenal',    chips:['Web','Copy-paste'] },
  'csrf/checklist':{ doc:'content/csrf-checklist.md', title:'CSRF — Testing Checklist', chips:['Web','Per-target'] },
  'csrf/poc':      { doc:'content/csrf-poc.md',       title:'CSRF — PoC Scripts',       chips:['Web','Runnable scripts'] },
  'csrf/qa':       { doc:'content/csrf-qa.md',        title:'CSRF — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'websocket/guide':    { doc:'content/websocket-guide.md',     title:'WebSocket — Testing Guide',       chips:['Web','Critical: CSWSH / ATO'] },
  'websocket/arsenal':  { doc:'content/websocket-arsenal.md',   title:'WebSocket — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'websocket/checklist':{ doc:'content/websocket-checklist.md', title:'WebSocket — Testing Checklist',   chips:['Web','Per-endpoint'] },
  'websocket/poc':      { doc:'content/websocket-poc.md',       title:'WebSocket — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'websocket/qa':       { doc:'content/websocket-qa.md',        title:'WebSocket — Zero to Expert (Q&A)',chips:['Web','Study · 115+ Q'] },

  'idor/guide':    { doc:'content/idor-guide.md',     title:'IDOR — Testing Guide',       chips:['Web','Critical: BOLA / ATO / mass PII'] },
  'idor/arsenal':  { doc:'content/idor-arsenal.md',   title:'IDOR — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'idor/checklist':{ doc:'content/idor-checklist.md', title:'IDOR — Testing Checklist',   chips:['Web','Per-object'] },
  'idor/poc':      { doc:'content/idor-poc.md',       title:'IDOR — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'idor/qa':       { doc:'content/idor-qa.md',        title:'IDOR — Zero to Expert (Q&A)',chips:['Web','Study · 124+ Q'] },

  'racecondition/guide':    { doc:'content/racecondition-guide.md',     title:'Race Condition — Testing Guide',       chips:['Web','Critical: limit-overrun / ATO'] },
  'racecondition/arsenal':  { doc:'content/racecondition-arsenal.md',   title:'Race Condition — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'racecondition/checklist':{ doc:'content/racecondition-checklist.md', title:'Race Condition — Testing Checklist',   chips:['Web','Per-endpoint'] },
  'racecondition/poc':      { doc:'content/racecondition-poc.md',       title:'Race Condition — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'racecondition/qa':       { doc:'content/racecondition-qa.md',        title:'Race Condition — Zero to Expert (Q&A)',chips:['Web','Study · 119+ Q'] },

  'graphql/guide':    { doc:'content/graphql-guide.md',     title:'GraphQL — Testing Guide',       chips:['API','Critical: BOLA / injection / ATO'] },
  'graphql/arsenal':  { doc:'content/graphql-arsenal.md',   title:'GraphQL — Attack Arsenal',      chips:['API','Copy-paste'] },
  'graphql/checklist':{ doc:'content/graphql-checklist.md', title:'GraphQL — Testing Checklist',   chips:['API','Per-endpoint'] },
  'graphql/poc':      { doc:'content/graphql-poc.md',       title:'GraphQL — PoC Scripts',         chips:['API','Runnable scripts'] },
  'graphql/qa':       { doc:'content/graphql-qa.md',        title:'GraphQL — Zero to Expert (Q&A)',chips:['API','Study · 119+ Q'] },

  'cmdi/guide':    { doc:'content/cmdi-guide.md',     title:'Command Injection — Testing Guide',       chips:['Web','Critical: RCE'] },
  'cmdi/arsenal':  { doc:'content/cmdi-arsenal.md',   title:'Command Injection — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'cmdi/checklist':{ doc:'content/cmdi-checklist.md', title:'Command Injection — Testing Checklist',   chips:['Web','Per-parameter'] },
  'cmdi/poc':      { doc:'content/cmdi-poc.md',       title:'Command Injection — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'cmdi/qa':       { doc:'content/cmdi-qa.md',        title:'Command Injection — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'cors/guide':    { doc:'content/cors-guide.md',     title:'CORS — Testing Guide',       chips:['Web','High: data theft / ATO'] },
  'cors/arsenal':  { doc:'content/cors-arsenal.md',   title:'CORS — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'cors/checklist':{ doc:'content/cors-checklist.md', title:'CORS — Testing Checklist',   chips:['Web','Per-origin'] },
  'cors/poc':      { doc:'content/cors-poc.md',       title:'CORS — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'cors/qa':       { doc:'content/cors-qa.md',        title:'CORS — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'fileupload/guide':    { doc:'content/fileupload-guide.md',     title:'File Upload — Testing Guide',       chips:['Web','Critical: RCE'] },
  'fileupload/arsenal':  { doc:'content/fileupload-arsenal.md',   title:'File Upload — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'fileupload/checklist':{ doc:'content/fileupload-checklist.md', title:'File Upload — Testing Checklist',   chips:['Web','Per-upload'] },
  'fileupload/poc':      { doc:'content/fileupload-poc.md',       title:'File Upload — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'fileupload/qa':       { doc:'content/fileupload-qa.md',        title:'File Upload — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'hostheader/guide':    { doc:'content/hostheader-guide.md',     title:'Host Header Injection — Testing Guide',       chips:['Web','High: ATO / cache poisoning'] },
  'hostheader/arsenal':  { doc:'content/hostheader-arsenal.md',   title:'Host Header Injection — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'hostheader/checklist':{ doc:'content/hostheader-checklist.md', title:'Host Header Injection — Testing Checklist',   chips:['Web','Per-endpoint'] },
  'hostheader/poc':      { doc:'content/hostheader-poc.md',       title:'Host Header Injection — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'hostheader/qa':       { doc:'content/hostheader-qa.md',        title:'Host Header Injection — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'jsfiles/guide':    { doc:'content/jsfiles-guide.md',     title:'JavaScript Files — Testing Guide',       chips:['Web','Recon · secrets / endpoints'] },
  'jsfiles/arsenal':  { doc:'content/jsfiles-arsenal.md',   title:'JavaScript Files — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'jsfiles/checklist':{ doc:'content/jsfiles-checklist.md', title:'JavaScript Files — Testing Checklist',   chips:['Web','Per-target'] },
  'jsfiles/poc':      { doc:'content/jsfiles-poc.md',       title:'JavaScript Files — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'jsfiles/qa':       { doc:'content/jsfiles-qa.md',        title:'JavaScript Files — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'ldap/guide':    { doc:'content/ldap-guide.md',     title:'LDAP Injection — Testing Guide',       chips:['Web','Critical: auth-bypass / ATO / disclosure'] },
  'ldap/arsenal':  { doc:'content/ldap-arsenal.md',   title:'LDAP Injection — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'ldap/checklist':{ doc:'content/ldap-checklist.md', title:'LDAP Injection — Testing Checklist',   chips:['Web','Per-sink'] },
  'ldap/poc':      { doc:'content/ldap-poc.md',       title:'LDAP Injection — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'ldap/qa':       { doc:'content/ldap-qa.md',        title:'LDAP Injection — Zero to Expert (Q&A)',chips:['Web','Study · 100 Q'] },

  'lfi/guide':    { doc:'content/lfi-guide.md',     title:'LFI — Testing Guide',       chips:['Web','Critical: RCE / source disclosure'] },
  'lfi/arsenal':  { doc:'content/lfi-arsenal.md',   title:'LFI — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'lfi/checklist':{ doc:'content/lfi-checklist.md', title:'LFI — Testing Checklist',   chips:['Web','Per-parameter'] },
  'lfi/poc':      { doc:'content/lfi-poc.md',       title:'LFI — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'lfi/qa':       { doc:'content/lfi-qa.md',        title:'LFI — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'rfi/guide':    { doc:'content/rfi-guide.md',     title:'RFI — Testing Guide',       chips:['Web','Critical: RCE'] },
  'rfi/arsenal':  { doc:'content/rfi-arsenal.md',   title:'RFI — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'rfi/checklist':{ doc:'content/rfi-checklist.md', title:'RFI — Testing Checklist',   chips:['Web','Per-parameter'] },
  'rfi/poc':      { doc:'content/rfi-poc.md',       title:'RFI — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'rfi/qa':       { doc:'content/rfi-qa.md',        title:'RFI — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'smuggling/guide':    { doc:'content/smuggling-guide.md',     title:'Request Smuggling — Testing Guide',       chips:['Web','Critical: desync / cache poisoning'] },
  'smuggling/arsenal':  { doc:'content/smuggling-arsenal.md',   title:'Request Smuggling — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'smuggling/checklist':{ doc:'content/smuggling-checklist.md', title:'Request Smuggling — Testing Checklist',   chips:['Web','Per-endpoint'] },
  'smuggling/poc':      { doc:'content/smuggling-poc.md',       title:'Request Smuggling — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'smuggling/qa':       { doc:'content/smuggling-qa.md',        title:'Request Smuggling — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'ssrf/guide':    { doc:'content/ssrf-guide.md',     title:'SSRF — Testing Guide',       chips:['Web','Critical: cloud creds / RCE'] },
  'ssrf/arsenal':  { doc:'content/ssrf-arsenal.md',   title:'SSRF — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'ssrf/checklist':{ doc:'content/ssrf-checklist.md', title:'SSRF — Testing Checklist',   chips:['Web','Per-parameter'] },
  'ssrf/poc':      { doc:'content/ssrf-poc.md',       title:'SSRF — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'ssrf/qa':       { doc:'content/ssrf-qa.md',        title:'SSRF — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'sqli/guide':    { doc:'content/sqli-guide.md',     title:'SQL Injection — Testing Guide',       chips:['Web','Critical: RCE / dump / auth-bypass'] },
  'sqli/arsenal':  { doc:'content/sqli-arsenal.md',   title:'SQL Injection — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'sqli/checklist':{ doc:'content/sqli-checklist.md', title:'SQL Injection — Testing Checklist',   chips:['Web','Per-parameter'] },
  'sqli/poc':      { doc:'content/sqli-poc.md',       title:'SQL Injection — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'sqli/qa':       { doc:'content/sqli-qa.md',        title:'SQL Injection — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },

  'ssti/guide':    { doc:'content/ssti-guide.md',     title:'SSTI — Testing Guide',       chips:['Web','Critical: RCE'] },
  'ssti/arsenal':  { doc:'content/ssti-arsenal.md',   title:'SSTI — Attack Arsenal',      chips:['Web','Copy-paste'] },
  'ssti/checklist':{ doc:'content/ssti-checklist.md', title:'SSTI — Testing Checklist',   chips:['Web','Per-parameter'] },
  'ssti/poc':      { doc:'content/ssti-poc.md',       title:'SSTI — PoC Scripts',         chips:['Web','Runnable scripts'] },
  'ssti/qa':       { doc:'content/ssti-qa.md',        title:'SSTI — Zero to Expert (Q&A)',chips:['Web','Study · 100+ Q'] },
};

/* Per-script code pages: click a script on a PoC index → its own page showing the source.
   Each entry: [route-slug, file (relative to the kit's poc folder), language]. */
function registerCode(prefix, folder, label, items, chips){
  items.forEach(([slug, file, lang])=>{
    DOCS[prefix+'/poc/'+slug] = {
      type:'code', file:'content/'+folder+'/'+file, lang,
      title: label+' PoC — '+file.split('/').pop(), nav:prefix+'/poc', back:prefix+'/poc',
      chips: chips || ['Web','PoC script']
    };
  });
}
registerCode('jwt','jwt-poc','JWT',[
  ['jwt_common','jwt_common.py','python'], ['alg_none','alg_none.py','python'],
  ['rs256_to_hs256','rs256_to_hs256.py','python'], ['kid_injection','kid_injection.py','python'],
  ['jwks_server','jwks_server.py','python'], ['jwk_inject','jwk_inject.py','python'],
  ['forge_token','forge_token.py','python'], ['jwe_dos_token','jwe_dos_token.py','python'],
]);
registerCode('xss','xss-poc','XSS',[
  ['poc-listener','poc-listener.py','python'], ['blind_xss','blind_xss.js','javascript'],
  ['cookie_steal','cookie_steal.js','javascript'], ['token_exfil','token_exfil.js','javascript'],
  ['account_takeover','account_takeover.js','javascript'], ['phish_overlay','phish_overlay.js','javascript'],
  ['keylogger','keylogger.js','javascript'], ['internal_scan','internal_scan.js','javascript'],
]);
registerCode('csrf','csrf-poc','CSRF',[
  ['csrf_poc_generator','csrf_poc_generator.py','python'],
  ['templates-form_post','templates/form_post.html','html'], ['templates-get_nav','templates/get_nav.html','html'],
  ['templates-json_textplain','templates/json_textplain.html','html'], ['templates-multipart','templates/multipart.html','html'],
  ['templates-login_csrf','templates/login_csrf.html','html'], ['templates-cors_cred','templates/cors_cred.html','html'],
  ['clickjack_csrf','clickjack_csrf.html','html'],
]);
registerCode('recon','recon-poc','Recon',[
  ['x8bit_recon','x8bit_recon.sh','bash'], ['recon','recon.sh','bash'], ['monitor','monitor.sh','bash'],
  ['takeover_check','takeover_check.sh','bash'], ['origin_ip','origin_ip.sh','bash'],
  ['js_extract','js_extract.sh','bash'], ['keys','keys.sh','bash'], ['setup','setup.sh','bash'],
  ['setup-recon-env','setup-recon-env.sh','bash'], ['config-env-example','config.env.example','bash'],
]);
registerCode('websocket','websocket-poc','WebSocket',[
  ['cswsh_poc','cswsh_poc.html','html'],
  ['ws_client','ws_client.py','python'],
  ['ws_ratelimit_test','ws_ratelimit_test.py','python'],
]);
registerCode('idor','idor-poc','IDOR',[
  ['idor_replay_diff','idor_replay_diff.py','python'],
  ['id_enumerator','id_enumerator.py','python'],
  ['graphql_node_sweep','graphql_node_sweep.py','python'],
]);
registerCode('racecondition','racecondition-poc','Race Condition',[
  ['race_single_packet','race_single_packet.py','python'],
  ['race_otp_bruteforce','race_otp_bruteforce.py','python'],
  ['parallel_fire','parallel_fire.py','python'],
]);
registerCode('graphql','graphql-poc','GraphQL',[
  ['introspect','introspect.py','python'],
  ['node_enumerator','node_enumerator.py','python'],
  ['batch_ratelimit_test','batch_ratelimit_test.py','python'],
], ['API','PoC script']);
registerCode('cmdi','cmdi-poc','Command Injection',[
  ['cmdi_fuzz','cmdi_fuzz.py','python'], ['evasion','evasion.py','python'],
  ['revshell','revshell.py','python'], ['oob_listen','oob_listen.md','markdown'],
]);
registerCode('cors','cors-poc','CORS',[
  ['cors_scan','cors_scan.py','python'], ['exfil','exfil.html','html'],
  ['null_iframe','null_iframe.html','html'], ['cswsh','cswsh.html','html'],
]);
registerCode('fileupload','fileupload-poc','File Upload',[
  ['webshell_marker_php','webshell_marker.php','php'], ['webshell_marker_phtml','webshell_marker.phtml','php'],
  ['webshell_marker_jsp','webshell_marker.jsp','xml'], ['webshell_marker_aspx','webshell_marker.aspx','xml'],
  ['xss_svg','xss.svg','xml'], ['xxe_svg','xxe.svg','xml'],
  ['xxe_oob_svg','xxe_oob.svg','xml'], ['xxe_oob_dtd','xxe_oob.dtd','xml'],
  ['htaccess_poc','htaccess_poc.txt','apache'], ['user_ini_poc','user_ini_poc.txt','ini'],
  ['make_polyglot','make_polyglot.sh','bash'], ['make_zipslip','make_zipslip.py','python'],
  ['make_symlink_tar','make_symlink_tar.sh','bash'], ['exif_rce_notes','exif_rce_notes.md','markdown'],
  ['upload_fuzz','upload_fuzz.sh','bash'],
]);
registerCode('hostheader','hostheader-poc','Host Header Injection',[
  ['hosthdr_probe','hosthdr_probe.py','python'], ['reset_poison','reset_poison.py','python'],
  ['cache_poison','cache_poison.py','python'], ['wcd_test','wcd_test.py','python'],
]);
registerCode('jsfiles','jsfiles-poc','JavaScript Files',[
  ['js_harvest','js_harvest.sh','bash'], ['secret_scan','secret_scan.py','python'],
  ['endpoints','endpoints.py','python'], ['dom_sinks','dom_sinks.py','python'],
  ['sourcemap_unpack','sourcemap_unpack.py','python'],
]);
registerCode('ldap','ldap-poc','LDAP Injection',[
  ['ldap_fuzz','ldap_fuzz.py','python'], ['ldap_blind','ldap_blind.py','python'],
  ['ldapsearch_cheat','ldapsearch_cheat.md','markdown'],
]);
registerCode('lfi','lfi-poc','LFI',[
  ['lfi_fuzz','lfi_fuzz.py','python'], ['phpfilter_dump','phpfilter_dump.py','python'],
  ['filter_chain_rce','filter_chain_rce.py','python'], ['logpoison','logpoison.py','python'],
]);
registerCode('rfi','rfi-poc','RFI',[
  ['payload_host','payload_host.py','python'], ['rfi_probe','rfi_probe.py','python'],
]);
registerCode('smuggling','smuggling-poc','Request Smuggling',[
  ['desync_timing','desync_timing.py','python'], ['build_smuggle','build_smuggle.py','python'],
]);
registerCode('ssrf','ssrf-poc','SSRF',[
  ['ip_encoder','ip_encoder.py','python'], ['redirect_server','redirect_server.py','python'],
  ['gopher_redis','gopher_redis.py','python'], ['ssrf_probe','ssrf_probe.sh','bash'],
]);
registerCode('sqli','sqli-poc','SQL Injection',[
  ['sqli_fuzz','sqli_fuzz.py','python'], ['sqli_blind','sqli_blind.py','python'],
  ['sqlmap_cheat','sqlmap_cheat.md','markdown'],
]);
registerCode('ssti','ssti-poc','SSTI',[
  ['ssti_detect','ssti_detect.py','python'], ['ssti_rce','ssti_rce.py','python'],
]);

const RECON_PAGES = [
  { label:'Web Recon Guide',      route:'recon/guide' },
  { label:'Recon Arsenal',        route:'recon/arsenal' },
  { label:'Recon Checklist',      route:'recon/checklist' },
  { label:'Scripts',              route:'recon/poc' },
  { label:'Zero to Expert (Q&A)', route:'recon/qa' },
];
const JWT_PAGES = [
  { label:'Testing Guide',        route:'jwt/guide' },
  { label:'Attack Arsenal',       route:'jwt/arsenal' },
  { label:'Testing Checklist',    route:'jwt/checklist' },
  { label:'PoC Scripts',          route:'jwt/poc' },
  { label:'Zero to Expert (Q&A)', route:'jwt/qa' },
];
const XSS_PAGES = [
  { label:'Testing Guide',        route:'xss/guide' },
  { label:'Payload Arsenal',      route:'xss/arsenal' },
  { label:'Testing Checklist',    route:'xss/checklist' },
  { label:'PoC Scripts',          route:'xss/poc' },
  { label:'Zero to Expert (Q&A)', route:'xss/qa' },
];
const CSRF_PAGES = [
  { label:'Testing Guide',        route:'csrf/guide' },
  { label:'Attack Arsenal',       route:'csrf/arsenal' },
  { label:'Testing Checklist',    route:'csrf/checklist' },
  { label:'PoC Scripts',          route:'csrf/poc' },
  { label:'Zero to Expert (Q&A)', route:'csrf/qa' },
];
const WEBSOCKET_PAGES = [
  { label:'Testing Guide',        route:'websocket/guide' },
  { label:'Attack Arsenal',       route:'websocket/arsenal' },
  { label:'Testing Checklist',    route:'websocket/checklist' },
  { label:'PoC Scripts',          route:'websocket/poc' },
  { label:'Zero to Expert (Q&A)', route:'websocket/qa' },
];
const IDOR_PAGES = [
  { label:'Testing Guide',        route:'idor/guide' },
  { label:'Attack Arsenal',       route:'idor/arsenal' },
  { label:'Testing Checklist',    route:'idor/checklist' },
  { label:'PoC Scripts',          route:'idor/poc' },
  { label:'Zero to Expert (Q&A)', route:'idor/qa' },
];
const RACECONDITION_PAGES = [
  { label:'Testing Guide',        route:'racecondition/guide' },
  { label:'Attack Arsenal',       route:'racecondition/arsenal' },
  { label:'Testing Checklist',    route:'racecondition/checklist' },
  { label:'PoC Scripts',          route:'racecondition/poc' },
  { label:'Zero to Expert (Q&A)', route:'racecondition/qa' },
];
const GRAPHQL_PAGES = [
  { label:'Testing Guide',        route:'graphql/guide' },
  { label:'Attack Arsenal',       route:'graphql/arsenal' },
  { label:'Testing Checklist',    route:'graphql/checklist' },
  { label:'PoC Scripts',          route:'graphql/poc' },
  { label:'Zero to Expert (Q&A)', route:'graphql/qa' },
];
function kitPages(prefix){
  return [
    { label:'Testing Guide',        route:prefix+'/guide' },
    { label:'Attack Arsenal',       route:prefix+'/arsenal' },
    { label:'Testing Checklist',    route:prefix+'/checklist' },
    { label:'PoC Scripts',          route:prefix+'/poc' },
    { label:'Zero to Expert (Q&A)', route:prefix+'/qa' },
  ];
}
const CMDI_PAGES       = kitPages('cmdi');
const CORS_PAGES       = kitPages('cors');
const FILEUPLOAD_PAGES = kitPages('fileupload');
const HOSTHEADER_PAGES = kitPages('hostheader');
const JSFILES_PAGES    = kitPages('jsfiles');
const LDAP_PAGES       = kitPages('ldap');
const LFI_PAGES        = kitPages('lfi');
const RFI_PAGES        = kitPages('rfi');
const SMUGGLING_PAGES  = kitPages('smuggling');
const SQLI_PAGES       = kitPages('sqli');
const SSRF_PAGES       = kitPages('ssrf');
const SSTI_PAGES       = kitPages('ssti');

const NAV = [
  { kind:'home', route:'about', label:'About' },
  { kind:'section', label:'Web', open:true, items:[
    { label:'Recon', kit:true, pages:RECON_PAGES },   // pinned to the top of Web
    { label:'Clickjacking', soon:true },
    { label:'Command Injection', kit:true, pages:CMDI_PAGES },
    { label:'CORS', kit:true, pages:CORS_PAGES },
    { label:'CSRF', kit:true, pages:CSRF_PAGES },
    { label:'File Upload', kit:true, pages:FILEUPLOAD_PAGES },
    { label:'Host Header Injection', kit:true, pages:HOSTHEADER_PAGES },
    { label:'IDOR / BOLA', kit:true, pages:IDOR_PAGES },
    { label:'JavaScript Files', kit:true, pages:JSFILES_PAGES },
    { label:'JWT', kit:true, pages:JWT_PAGES },
    { label:'LDAP', kit:true, pages:LDAP_PAGES },
    { label:'LFI', kit:true, pages:LFI_PAGES },
    { label:'Race Condition', kit:true, pages:RACECONDITION_PAGES },
    { label:'Request Smuggling', kit:true, pages:SMUGGLING_PAGES },
    { label:'RFI', kit:true, pages:RFI_PAGES },
    { label:'SQL Injection', kit:true, pages:SQLI_PAGES },
    { label:'SSRF', kit:true, pages:SSRF_PAGES },
    { label:'SSTI', kit:true, pages:SSTI_PAGES },
    { label:'WebSocket', kit:true, pages:WEBSOCKET_PAGES },
    { label:'XSS', kit:true, pages:XSS_PAGES },
  ]},
  { kind:'section', label:'API', open:false, items:[
    { label:'GraphQL', kit:true, pages:GRAPHQL_PAGES },
    { label:'REST', soon:true },
  ]},
  { kind:'section', label:'Mobile', open:false, groups:[
    { label:'Android', open:false, items:[ { label:'Coming soon', soon:true } ]},
    { label:'iOS',     open:false, items:[ { label:'Coming soon', soon:true } ]},
  ]},
];

/* ---- Recently Updated (Chirpy-style right panel) ---- */
/* one entry per TOPIC (kit) — just the main name + date; links to the kit's guide */
const RECENT = [
  { label:'SQL Injection',  route:'sqli/guide',           date:'Jun 2026' },
  { label:'LDAP',           route:'ldap/guide',           date:'Jun 2026' },
  { label:'WebSocket',      route:'websocket/guide',      date:'Jun 2026' },
  { label:'IDOR',           route:'idor/guide',           date:'Jun 2026' },
  { label:'Race Condition', route:'racecondition/guide',  date:'Jun 2026' },
  { label:'GraphQL',        route:'graphql/guide',        date:'Jun 2026' },
  { label:'XSS',            route:'xss/guide',            date:'Jun 2026' },
  { label:'CSRF',           route:'csrf/guide',           date:'Jun 2026' },
  { label:'JWT',            route:'jwt/guide',            date:'Jun 2026' },
  { label:'Recon',          route:'recon/guide',          date:'Jun 2026' },
];
function renderRecent(){
  const ul = document.getElementById('recent'); if(!ul) return;
  ul.innerHTML = '';
  RECENT.slice(0,6).forEach(it=>{
    const li = el('li','recent-item');
    const a = el('a'); a.href = '#/'+it.route; a.textContent = it.label;
    const d = elText('span','recent-date', it.date);
    li.appendChild(a); li.appendChild(d); ul.appendChild(li);
  });
}

/* ---- build the sidebar (Section ▸ Group dropdown ▸ Kit ▸ pages) ---- */
function buildNav(){
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  NAV.forEach(node=>{
    if(node.kind==='home'){ const a=link(node.label,node.route); a.classList.add('nav-home'); nav.appendChild(a); return; }
    const sec = el('div','nav-sec'+(node.open?'':' collapsed'));
    const grp = el('button','grp'); grp.innerHTML = `<span>${node.label}</span><span class="chev">▾</span>`;
    grp.onclick = ()=> sec.classList.toggle('collapsed');
    sec.appendChild(grp);
    const ch = el('div','children');
    if(node.items){
      // section with a flat list of attacks (e.g. Web — alphabetical)
      node.items.forEach(it=> ch.appendChild(buildItem(it)));
    } else {
      // section with collapsible sub-groups (e.g. Mobile → Android / iOS)
      (node.groups||[]).forEach(g=>{
        const grpEl = el('div','nav-group'+(g.open?'':' collapsed'));
        const gh = el('button','group-head'); gh.innerHTML = `<span>${g.label}</span><span class="chev">▾</span>`;
        gh.onclick = ()=> grpEl.classList.toggle('collapsed');
        const gch = el('div','group-children');
        (g.items||[]).forEach(it=> gch.appendChild(buildItem(it)));
        grpEl.appendChild(gh); grpEl.appendChild(gch);
        ch.appendChild(grpEl);
      });
    }
    sec.appendChild(ch);
    nav.appendChild(sec);
  });
}
function buildItem(it){
  if(it.kit){
    const kit = el('div','kit collapsed');
    const head = el('button','kit-head');
    head.innerHTML = `<span class="dot"></span><span>${it.label}</span><span class="kchev">▾</span>`;
    head.onclick = ()=> kit.classList.toggle('collapsed');
    const pages = el('div','kit-pages');
    it.pages.forEach(p=> pages.appendChild(link(p.label, p.route)));
    kit.appendChild(head); kit.appendChild(pages);
    return kit;
  }
  if(it.soon){
    const a = el('div','nav-link soon');
    a.innerHTML = `<span class="dot"></span><span>${it.label}</span><span class="badge">soon</span>`;
    return a;
  }
  return link(it.label, it.route);
}
function el(t,c){const e=document.createElement(t);if(c)e.className=c;return e;}
function elText(t,c,txt){const e=el(t,c);e.textContent=txt;return e;}
function link(label,route){
  const a=el('a','nav-link'); a.href='#/'+route; a.dataset.route=route;
  a.innerHTML=`<span class="dot"></span><span>${label}</span>`;
  return a;
}

/* ---- GitHub-compatible heading slugger (so the in-doc Table-of-Contents anchors resolve) ---- */
function makeSlugger(){
  const seen = Object.create(null);
  return (text)=>{
    let s = (text||'').toLowerCase().trim()
      .replace(/[^\p{L}\p{N}\s_-]/gu,'')   // drop punctuation/symbols; keep letters, numbers, whitespace, _ , -
      .replace(/\s/g,'-');                  // EACH whitespace -> one hyphen (matches GitHub's '--' on " — ")
    if(s in seen){ seen[s]++; s = `${s}-${seen[s]}`; } else { seen[s]=0; }
    return s;
  };
}
function assignHeadingIds(root){
  const slug = makeSlugger();
  root.querySelectorAll('h1,h2,h3,h4,h5,h6').forEach(h=>{ h.id = slug(h.textContent); });
}

/* ---- Notion-style on-page Table of Contents (right floating minimap → expands on hover) ---- */
let _tocScrollHandler = null;
function buildPageToc(root){
  const toc = document.getElementById('pageToc');
  if(!toc) return;
  if(_tocScrollHandler){ window.removeEventListener('scroll', _tocScrollHandler); _tocScrollHandler = null; }
  toc.innerHTML = ''; toc.classList.remove('show'); document.body.classList.remove('has-toc');
  const heads = root ? Array.from(root.querySelectorAll('h1,h2,h3')).filter(h=> h.id && h.textContent.trim()) : [];
  if(heads.length < 3) return;                         // too short to be worth a TOC

  const inner = el('div','toc-inner');
  inner.appendChild(elText('div','toc-title','On this page'));
  const listEl = el('div','toc-list');
  const items = [];
  heads.forEach(h=>{
    const lvl = +h.tagName[1];
    const a = el('a','toc-item lvl-'+lvl);
    a.href = '#'+h.id; a.dataset.target = h.id; a.title = h.textContent;
    a.appendChild(elText('span','toc-text', h.textContent));
    a.appendChild(el('span','toc-dash'));
    a.addEventListener('click',(e)=>{ e.preventDefault(); scrollToAnchor(h.id); });
    listEl.appendChild(a);
    items.push({ a, h });
  });
  inner.appendChild(listEl);
  toc.appendChild(inner);
  toc.classList.add('show'); document.body.classList.add('has-toc');

  // scroll-spy: the last heading scrolled past 130px from the top is the active one
  const spy = ()=>{
    let active = items[0];
    for(const it of items){ if(it.h.getBoundingClientRect().top <= 130) active = it; else break; }
    items.forEach(it=> it.a.classList.toggle('active', it === active));
    if(inner.scrollHeight > inner.clientHeight){       // keep the active marker visible in a tall list
      inner.scrollTop = Math.max(0, active.a.offsetTop - inner.clientHeight / 2);
    }
  };
  _tocScrollHandler = ()=> requestAnimationFrame(spy);
  window.addEventListener('scroll', _tocScrollHandler, { passive:true });
  spy();
}

/* ---- markdown rendering (HTML sanitised — these guides contain live payloads) ---- */
function renderMarkdown(md){
  marked.setOptions({ gfm:true, breaks:false });
  return DOMPurify.sanitize(marked.parse(md), {USE_PROFILES:{html:true}});
}

/* ---- scroll to an in-page anchor (TOC links) ---- */
function scrollToAnchor(id){
  if(!id) return;
  const find = ()=> document.getElementById(id) || document.getElementById(decodeURIComponent(id));
  let elt = find();
  const go = ()=>{ const e2=find(); if(e2){ e2.scrollIntoView({behavior:'smooth',block:'start'}); return true; } return false; };
  if(!go()) setTimeout(go, 150);
}

function chipHtml(chips){
  return (chips||[]).map(c=>{
    const cls = /crit/i.test(c)?'chip crit':(/server|client|web/i.test(c)?'chip acc':'chip');
    return `<span class="${cls}">${c}</span>`;
  }).join('');
}

async function route(){
  let r = location.hash.replace(/^#\//,'') || 'about';
  if(!DOCS[r]) r = 'about';
  const meta = DOCS[r];
  const navR = meta.nav || r;                  // code pages highlight their parent ('jwt/poc')
  const content = document.getElementById('content');
  content.innerHTML = `<div class="loading">Loading…</div>`;
  document.querySelectorAll('.nav-link').forEach(a=>a.classList.toggle('active', a.dataset.route===navR));
  // expand the FULL chain that owns the active page (kit → group → section) so it's always visible
  const activeLink = document.querySelector('.nav-link.active');
  document.querySelectorAll('.kit').forEach(k=>k.classList.remove('active-kit'));
  if(activeLink){
    const k = activeLink.closest('.kit');       if(k){ k.classList.remove('collapsed'); k.classList.add('active-kit'); }
    const g = activeLink.closest('.nav-group');  if(g) g.classList.remove('collapsed');
    const s = activeLink.closest('.nav-sec');    if(s) s.classList.remove('collapsed');
  }
  try{
    // ----- per-script CODE page (click a script on the PoC index) -----
    if(meta.type === 'code'){
      const res = await fetch(meta.file, {cache:'no-cache'});
      if(!res.ok) throw new Error('HTTP '+res.status);
      const codeText = await res.text();
      content.innerHTML =
        (meta.chips?`<div class="doc-meta">${chipHtml(meta.chips)}</div>`:'') +
        `<div class="md"><h1>${meta.file.split('/').pop()}</h1>` +
        `<p><a href="#/${meta.back}">← Back to PoC Scripts</a></p></div>` +
        `<div class="site-foot">x8bitranjit · security knowledge base · authorized testing only.</div>`;
      const md = content.querySelector('.md');
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.className = 'language-' + (meta.lang||'plaintext');
      code.textContent = codeText;            // textContent = no HTML execution (safe)
      pre.appendChild(code);
      md.appendChild(pre);
      try{ hljs.highlightElement(code); }catch(e){}
      buildPageToc(null);                       // code pages have no outline
      document.title = meta.title + ' · x8bitranjit';
      window.scrollTo(0,0);
      document.querySelector('.sidebar').classList.remove('open');
      document.querySelector('.overlay')?.classList.remove('show');
      return;
    }
    // ----- normal markdown page -----
    const res = await fetch(meta.doc, {cache:'no-cache'});
    if(!res.ok) throw new Error('HTTP '+res.status);
    const md = await res.text();
    content.innerHTML =
      (meta.chips&&meta.chips.length?`<div class="doc-meta">${chipHtml(meta.chips)}</div>`:'') +
      `<div class="md">${renderMarkdown(md)}</div>` +
      `<div class="site-foot">x8bitranjit · security knowledge base · authorized testing only.</div>`;
    const mdRoot = content.querySelector('.md');
    assignHeadingIds(mdRoot);
    buildPageToc(mdRoot);
    mdRoot.querySelectorAll('pre code').forEach(b=>{ try{hljs.highlightElement(b);}catch(e){} });
    document.title = meta.title + ' · x8bitranjit';
    window.scrollTo(0,0);
  }catch(e){
    content.innerHTML = `<div class="md"><h1>Couldn't load this page</h1>
      <p>${meta.doc || meta.file} — ${e.message}.</p>
      <blockquote>If you opened this with <code>file://</code>, run a local server instead:
      <br><code>cd site &amp;&amp; python -m http.server 8080</code> then open
      <a href="http://localhost:8080">http://localhost:8080</a>. On GitHub Pages it loads directly.</blockquote></div>`;
    buildPageToc(null);
  }
  document.querySelector('.sidebar').classList.remove('open');
  document.querySelector('.overlay')?.classList.remove('show');
}

/* ---- only #/route changes the page; #anchor scrolls in place ---- */
function onHashChange(){
  const h = location.hash;
  if(h.startsWith('#/') || h==='' || h==='#'){ route(); }
  else { scrollToAnchor(h.slice(1)); }
}

/* ---- intercept in-doc TOC clicks so they scroll instead of clobbering the route ---- */
function wireContentLinks(){
  document.getElementById('content').addEventListener('click', (e)=>{
    const a = e.target.closest('a[href^="#"]');
    if(!a) return;
    const href = a.getAttribute('href');
    if(href.startsWith('#/')) return;            // real page route → let the router handle it
    e.preventDefault();                          // in-page anchor → scroll, keep the current page in the URL
    scrollToAnchor(href.slice(1));
  });
}

/* ---- mobile drawer ---- */
function wireMobile(){
  const sb=document.querySelector('.sidebar'), ov=document.querySelector('.overlay');
  document.getElementById('menuBtn').onclick=()=>{sb.classList.toggle('open');ov.classList.toggle('show');};
  ov.onclick=()=>{sb.classList.remove('open');ov.classList.remove('show');};
}

window.addEventListener('hashchange', onHashChange);
window.addEventListener('DOMContentLoaded', ()=>{ buildNav(); renderRecent(); wireMobile(); wireContentLinks(); route(); });
