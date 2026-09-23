/**
 * Cheat Detection Pattern Database
 * 300+ signatures organized by category for comprehensive mod analysis
 */

const CHEAT_PATTERNS = {
  combat: {
    label: '⚔️ Combat',
    patterns: [
      { name: 'KillAura', regex: /kill\s*aura|killaura/i, severity: 'critical' },
      { name: 'AimAssist', regex: /aim\s*assist|aimassist|aimhelper/i, severity: 'high' },
      { name: 'AutoCrystal', regex: /auto\s*crystal|autocrystal|crystalaura/i, severity: 'critical' },
      { name: 'AutoHitCrystal', regex: /autohit\s*crystal|autohitcrystal/i, severity: 'critical' },
      { name: 'TriggerBot', regex: /trigger\s*bot|triggerbot|triggerbot/i, severity: 'high' },
      { name: 'SilentAim', regex: /silent\s*aim|silentaim/i, severity: 'high' },
      { name: 'Criticals', regex: /criticals?[^a-z]/i, severity: 'medium' },
      { name: 'Reach', regex: /\breach\s*hack|reachhack|\breach\s*mod|\breach\s*bypass/i, severity: 'high' },
      { name: 'ShieldBreaker', regex: /shield\s*breaker|shieldbreaker/i, severity: 'high' },
      { name: 'ShieldDisabler', regex: /shield\s*disabler|shielddisabler/i, severity: 'high' },
      { name: 'AxeSpam', regex: /axe\s*spam|axespam/i, severity: 'medium' },
      { name: 'BowAimbot', regex: /bow\s*aimbot|bowaimbot/i, severity: 'high' },
      { name: 'AutoCrit', regex: /auto\s*crit|autocrit/i, severity: 'medium' },
      { name: 'SweepAura', regex: /sweep\s*aura|sweepaura/i, severity: 'medium' },
      { name: 'MultiAura', regex: /multi\s*aura|multiaura/i, severity: 'high' },
      { name: 'TPAura', regex: /tp\s*aura|tpaura/i, severity: 'critical' },
      { name: 'HitBoxes', regex: /hit\s*boxes|hitboxes/i, severity: 'medium' },
      { name: 'AutoArmor', regex: /auto\s*armor|autoarmor/i, severity: 'medium' },
      { name: 'AutoTotem', regex: /auto\s*totem|autototem/i, severity: 'high' },
      { name: 'HoverTotem', regex: /hover\s*totem|hovertotem/i, severity: 'medium' },
      { name: 'InventoryTotem', regex: /inventory\s*totem|inventorytotem/i, severity: 'medium' },
      { name: 'AutoPot', regex: /auto\s*potion|autopot/i, severity: 'medium' },
      { name: 'AutoDoubleHand', regex: /auto\s*double\s*hand/i, severity: 'medium' },
      { name: 'PopSwitch', regex: /pop\s*switch|popswitch/i, severity: 'medium' },
      { name: 'MaceSwap', regex: /mace\s*swap|aceswap/i, severity: 'medium' },
      { name: 'StunSlam', regex: /stun\s*slam|stunslam/i, severity: 'medium' },
      { name: 'Velocity', regex: /\bvelocity\s*hack|\bvelocity\s*mod|\bvelocity\s*cancel|\bvelocity\s*ignore/i, severity: 'critical' },
      { name: 'AutoVelocity', regex: /auto\s*velocity|autovelocity/i, severity: 'high' },
      { name: 'NoAttackCooldown', regex: /no\s*attack\s*cooldown|noattackcooldown|attack\s*cooldown\s*reset/i, severity: 'medium' },
      { name: 'AutoClicker', regex: /auto\s*click|autoclick|autoclicker|fastclick|cps\s*mod/i, severity: 'critical' },
      { name: 'Aimbot', regex: /\baimbot\b|aim\s*bot/i, severity: 'critical' },
      { name: 'ReachHackBare', regex: /\breach\s*[=:]|reach\.enabled|reach\.range/i, severity: 'high' },
    ]
  },

  crystal: {
    label: '💎 Crystal / Anchor / Bed',
    patterns: [
      { name: 'AutoAnchor', regex: /auto\s*anchor|autoanchor/i, severity: 'critical' },
      { name: 'AnchorTweaks', regex: /anchor\s*tweaks|anchortweaks/i, severity: 'high' },
      { name: 'DoubleAnchor', regex: /double\s*anchor|doubleanchor/i, severity: 'high' },
      { name: 'SafeAnchor', regex: /safe\s*anchor|safeanchor/i, severity: 'medium' },
      { name: 'AirAnchor', regex: /air\s*anchor|airanchor/i, severity: 'high' },
      { name: 'AutoBed', regex: /auto\s*bed|autobed/i, severity: 'high' },
      { name: 'BedAura', regex: /bed\s*aura|bedaura/i, severity: 'critical' },
      { name: 'NoBounce', regex: /no\s*bounce|nobounce/i, severity: 'medium' },
      { name: 'LWFHCrystal', regex: /lwfh\s*crystal|lwfhrystal/i, severity: 'critical' },
      { name: 'CrystalOptimizer', regex: /crystal\s*optimizer|walksycrystal/i, severity: 'high' },
      { name: 'CrystalDamage', regex: /crystal\s*damage|crystaldamage/i, severity: 'medium' },
      { name: 'Nuker', regex: /\bnuker\b/i, severity: 'high' },
      { name: 'AutoEndCrystal', regex: /auto\s*end\s*crystal|autoendcrystal/i, severity: 'critical' },
    ]
  },

  movement: {
    label: '🏃 Movement',
    patterns: [
      { name: 'FlyHack', regex: /fly\s*hack|flyhack|fly\s*mod|fly\s*exploit/i, severity: 'critical' },
      { name: 'SpeedHack', regex: /speed\s*hack|speedhack|speed\s*mod|speed\s*boost/i, severity: 'critical' },
      { name: 'BHop', regex: /\bbhop\b|bunny\s*hop|bunnyhop/i, severity: 'high' },
      { name: 'AntiFall', regex: /anti\s*fall|antifall|no\s*fall|nofall/i, severity: 'high' },
      { name: 'NoKnockback', regex: /no\s*knockback|noknockback|anti\s*kb|antikb|anti\s*knockback/i, severity: 'critical' },
      { name: 'StepHack', regex: /step\s*hack|stephack|step\s*height|stepmod/i, severity: 'medium' },
      { name: 'WaterWalk', regex: /water\s*walk|waterwalk/i, severity: 'high' },
      { name: 'NoSlow', regex: /no\s*slow|noslow|slow\s*down\s*cancel/i, severity: 'high' },
      { name: 'JumpReset', regex: /jump\s*reset|jumpreset/i, severity: 'medium' },
      { name: 'SprintReset', regex: /sprint\s*reset|sprintreset/i, severity: 'medium' },
      { name: 'NoJumpDelay', regex: /no\s*jump\s*delay|nojumpdelay/i, severity: 'medium' },
      { name: 'ElytraSpeed', regex: /elytra\s*speed|elytraspeed/i, severity: 'medium' },
      { name: 'JesusWalk', regex: /jesus\s*walk|jesus\s*mod|jesuswalk|water\s*walking/i, severity: 'high' },
      { name: 'SpiderClimb', regex: /spider\s*climb|spiderclimb|spider\s*mod/i, severity: 'high' },
      { name: 'Scaffold', regex: /\bscaffold\s*mod|\bscaffoldwalk|\bscaffold\s*hack/i, severity: 'critical' },
      { name: 'AutoSprint', regex: /auto\s*sprint|autosprint/i, severity: 'medium' },
      { name: 'AutoWalk', regex: /auto\s*walk|autowalk/i, severity: 'low' },
      { name: 'Freelook', regex: /freelook|free\s*look|freecam/i, severity: 'medium' },
      { name: 'NoSlowdown', regex: /no\s*slowdown|noslowdown/i, severity: 'medium' },
      { name: 'Phase', regex: /\bphase\s*hack|\bphase\s*mod/i, severity: 'critical' },
      { name: 'Clip', regex: /\bclip\s*mod|\bclip\s*hack/i, severity: 'high' },
      { name: 'NoClip', regex: /noclip/i, severity: 'critical' },
    ]
  },

  visual: {
    label: '👁️ Visual / ESP',
    patterns: [
      { name: 'BlockESP', regex: /block\s*esp|blockesp/i, severity: 'high' },
      { name: 'PlayerESP', regex: /player\s*esp|playeresp/i, severity: 'high' },
      { name: 'EntityESP', regex: /entity\s*esp|entityesp/i, severity: 'high' },
      { name: 'XRayHack', regex: /xray\s*hack|xray\s*mod|xray\s*exploit/i, severity: 'high' },
      { name: 'XRay', regex: /\bxray\b|x[-]?ray/i, severity: 'medium' },
      { name: 'Tracers', regex: /\btracers?\b/i, severity: 'high' },
      { name: 'Freecam', regex: /\bfreecam\b|\bfree\s*cam\b/i, severity: 'high' },
      { name: 'FakeItem', regex: /fake\s*item|fakeitem/i, severity: 'high' },
      { name: 'NewChunks', regex: /new\s*chunks|newchunks/i, severity: 'medium' },
      { name: 'Nametags', regex: /nametag\s*mod|nametags\s*hack/i, severity: 'medium' },
      { name: 'ChestESP', regex: /chest\s*esp|chestesp/i, severity: 'high' },
      { name: 'ItemESP', regex: /item\s*esp|itemesp/i, severity: 'high' },
      { name: 'MobESP', regex: /mob\s*esp|mobesp/i, severity: 'medium' },
      { name: 'StorageESP', regex: /storage\s*esp|storageesp/i, severity: 'high' },
      { name: 'Waypoints', regex: /waypoints?\s*hack|waypoints?\s*cheat/i, severity: 'medium' },
      { name: 'Fullbright', regex: /\bfullbright\b|night\s*vision\s*hack/i, severity: 'low' },
      { name: 'ESP', regex: /\besp\s*mod|\besp\s*hack|\besp\s*player/i, severity: 'high' },
      { name: 'WallHack', regex: /wall\s*hack|wallhack/i, severity: 'high' },
      { name: 'OutlinePlayers', regex: /outline\s*players|player\s*outlines/i, severity: 'medium' },
    ]
  },

  automation: {
    label: '🤖 Automation',
    patterns: [
      { name: 'FastPlace', regex: /fast\s*place|fastplace/i, severity: 'high' },
      { name: 'ChestSteal', regex: /chest\s*steal|cheststeal|steal\s*chest/i, severity: 'critical' },
      { name: 'AutoEat', regex: /auto\s*eat|autoeat/i, severity: 'medium' },
      { name: 'AutoMine', regex: /auto\s*mine|automine/i, severity: 'medium' },
      { name: 'AutoFirework', regex: /auto\s*firework|autofirework/i, severity: 'low' },
      { name: 'ElytraSwap', regex: /elytra\s*swap|elytraswap/i, severity: 'medium' },
      { name: 'FastXP', regex: /fast\s*xp|fastxp/i, severity: 'medium' },
      { name: 'AutoBridge', regex: /auto\s*bridge|autobridge/i, severity: 'high' },
      { name: 'AutoBreach', regex: /auto\s*breach|autobreach/i, severity: 'high' },
      { name: 'AutoFarm', regex: /auto\s*farm|autofarm/i, severity: 'low' },
      { name: 'AutoSmelt', regex: /auto\s*smelt|autosmelt/i, severity: 'low' },
      { name: 'AutoSort', regex: /auto\s*sort|autosort/i, severity: 'low' },
      { name: 'AutoCraft', regex: /auto\s*craft|autocraft/i, severity: 'low' },
      { name: 'AutoFish', regex: /auto\s*fish|autofish/i, severity: 'medium' },
      { name: 'FastBreak', regex: /fast\s*break|fastbreak/i, severity: 'high' },
      { name: 'PacketMine', regex: /packet\s*mine|packetmine/i, severity: 'critical' },
      { name: 'AutoTool', regex: /auto\s*tool|autotool/i, severity: 'medium' },
      { name: 'AutoShear', regex: /auto\s*shear|autoshear/i, severity: 'low' },
    ]
  },

  pvpUtility: {
    label: '🛡️ PvP Utility',
    patterns: [
      { name: 'FakeLag', regex: /fake\s*lag|fakelag/i, severity: 'high' },
      { name: 'PingSpoof', regex: /ping\s*spool|pingspoof|ping\s*spoof/i, severity: 'high' },
      { name: 'FakeInv', regex: /fake\s*inv|fakeinv/i, severity: 'high' },
      { name: 'WTap', regex: /\bwtap\b|w-tap/i, severity: 'medium' },
      { name: 'FakeNick', regex: /fake\s*nick|fakenick|nick\s*hack/i, severity: 'high' },
      { name: 'PackSpoof', regex: /pack\s*spool|packspool|pack\s*spoof/i, severity: 'high' },
      { name: 'AntiKnockback', regex: /anti\s*knockback|antiknockback|anti\s*kb/i, severity: 'critical' },
      { name: 'AutoGap', regex: /auto\s*gap|autogap|auto\s*gapple/i, severity: 'medium' },
      { name: 'AutoPearl', regex: /auto\s*pearl|autopearl/i, severity: 'medium' },
      { name: 'AutoTPA', regex: /auto\s*tpa|autotpa/i, severity: 'medium' },
      { name: 'HitSelect', regex: /hit\s*select|hitselect/i, severity: 'medium' },
      { name: 'ComboBreaker', regex: /combo\s*breaker|combobreaker/i, severity: 'medium' },
      { name: 'SprintReset', regex: /sprint\s*reset|sprintreset/i, severity: 'medium' },
      { name: 'RodAim', regex: /rod\s*aim|rodaim/i, severity: 'medium' },
      { name: 'AutoRod', regex: /auto\s*rod|autorod/i, severity: 'medium' },
      { name: 'BlockHit', regex: /block\s*hit|blockhit/i, severity: 'medium' },
    ]
  },

  antiCheatBypass: {
    label: '🚫 Anti-Cheat Bypass',
    patterns: [
      { name: 'GrimBypass', regex: /grim\s*bypass|grimbypass|bypass.*grim|grim.*bypass/i, severity: 'critical' },
      { name: 'VulcanBypass', regex: /vulcan\s*bypass|vulcanbypass|bypass.*vulcan/i, severity: 'critical' },
      { name: 'MatrixBypass', regex: /matrix\s*bypass|matrixbypass|bypass.*matrix/i, severity: 'critical' },
      { name: 'AACBypass', regex: /aac\s*bypass|aacbypass|bypass.*aac/i, severity: 'critical' },
      { name: 'VerusDisabler', regex: /verus\s*disabler|verusdisabler|disabler.*verus/i, severity: 'critical' },
      { name: 'WatchdogBypass', regex: /watchdog\s*bypass|watchdogbypass|bypass.*watchdog/i, severity: 'critical' },
      { name: 'PacketFly', regex: /packet\s*fly|packetfly/i, severity: 'critical' },
      { name: 'Disabler', regex: /\bdisabler\b|\banti\s*cheat\s*disabler/i, severity: 'critical' },
      { name: 'Motion', regex: /motion\s*bypass|motionbypass/i, severity: 'high' },
      { name: 'NCPBypass', regex: /ncp\s*bypass|ncpbypass|bypass.*ncp/i, severity: 'critical' },
      { name: 'SpartanBypass', regex: /spartan\s*bypass|spartanbypass/i, severity: 'critical' },
      { name: 'IntaveBypass', regex: /intave\s*bypass|intavebypass/i, severity: 'critical' },
      { name: 'PolarBypass', regex: /polar\s*bypass|polarbypass/i, severity: 'critical' },
      { name: 'KarhuBypass', regex: /karhu\s*bypass|karhubypass/i, severity: 'critical' },
      { name: 'CerbBypass', regex: /cerb\s*bypass|cerbbypass/i, severity: 'critical' },
      { name: 'AntiCheat', regex: /anti\s*cheat\s*bypass|anticheat\s*bypass/i, severity: 'critical' },
      { name: 'Silent', regex: /silent\s*movement|silentmode|silent\s*mode/i, severity: 'high' },
      { name: 'Bypass', regex: /\bbypass\s*client|\bbypass\s*mod/i, severity: 'high' },
    ]
  },

  malware: {
    label: '🦠 Malware / RAT',
    patterns: [
      { name: 'SessionStealer', regex: /session\s*stealer|sessionstealer|steal.*session/i, severity: 'critical' },
      { name: 'TokenLogger', regex: /token\s*logger|tokenlogger|logger.*token/i, severity: 'critical' },
      { name: 'TokenGrabber', regex: /token\s*grabber|tokengrabber|grabber.*token/i, severity: 'critical' },
      { name: 'KeyLogger', regex: /key\s*logger|keylogger|key\s*logging/i, severity: 'critical' },
      { name: 'RemoteAccess', regex: /remote\s*access|remoteaccess|remote\s*control/i, severity: 'critical' },
      { name: 'ReverseShell', regex: /reverse\s*shell|reverseshell|shell\s*reverse/i, severity: 'critical' },
      { name: 'Backdoor', regex: /\bbackdoor\b|back\s*door/i, severity: 'critical' },
      { name: 'DataExfil', regex: /data\s*exfil|exfiltrat|exfil.*data/i, severity: 'critical' },
      { name: 'CredentialStealer', regex: /credential.*steal|stealer.*credential|password.*steal/i, severity: 'critical' },
      { name: 'BrowserStealer', regex: /browser.*steal|stealer.*browser|chrome.*steal|firefox.*steal/i, severity: 'critical' },
      { name: 'DiscordToken', regex: /discord.*token.*grab|grab.*discord.*token|discordtoken/i, severity: 'critical' },
      { name: 'ClipboardHijack', regex: /clipboard.*hijack|hijack.*clipboard|clipper|crypto.*clip/i, severity: 'high' },
      { name: 'CryptoStealer', regex: /crypto.*steal|wallet.*steal|steal.*wallet|crypto.*clip/i, severity: 'critical' },
      { name: 'MinecraftStealer', regex: /minecraft.*steal|steal.*minecraft|steal.*account|account.*steal/i, severity: 'critical' },
      { name: 'RAT', regex: /\brat\b.*mod|\brat\b.*client|trojan/i, severity: 'critical' },
    ]
  },

  knownClients: {
    label: '🎯 Known Cheat Clients',
    patterns: [
      { name: 'Asteria', regex: /\basteria\b/i, severity: 'critical' },
      { name: 'Stardust', regex: /\bstardust\s*(client|mod|hack)\b/i, severity: 'critical' },
      { name: 'Dortware', regex: /\bdort\s*ware\b|\bdortware\b/i, severity: 'critical' },
      { name: 'Celestial', regex: /\bcelestial\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'BleachHack', regex: /\bbleach\s*hack\b|\bbleachhack\b/i, severity: 'critical' },
      { name: 'CandyClient', regex: /\bcandy\s*client\b|\bcandyclient\b/i, severity: 'critical' },
      { name: 'VapeLite', regex: /\bvape\s*lite\b/i, severity: 'critical' },
      { name: 'RiseClient', regex: /\brise\s*client\b|\briseclient\b/i, severity: 'critical' },
      { name: 'MoonClient2', regex: /\bmoonclient\b|\bmoon\s*client\b/i, severity: 'critical' },
      { name: 'AimWare', regex: /\baim\s*ware\b|\baimware\b/i, severity: 'critical' },
      { name: 'Sensation', regex: /\bsensation\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'FiredCustomer', regex: /\bfiredcustomer\b/i, severity: 'critical' },
      { name: 'Zephyr', regex: /\bzephyr\s*(client|mod|hack)\b/i, severity: 'critical' },
      { name: 'Horion', regex: /\bhorion\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'CpsClient', regex: /\bcps\s*client\b|\bcpsclient\b/i, severity: 'high' },
      { name: 'SpartanClient', regex: /\bspartan\s*(client|hack|mod)\b/i, severity: 'critical' },
      { name: 'NorthClient', regex: /\bnorth\s*client\b|\bnorthclient\b/i, severity: 'critical' },
      { name: 'RavenXD', regex: /\braven\s*xd\b|\bravenxd\b/i, severity: 'critical' },
      { name: 'WurstPlus', regex: /\bwurst\s*plus\b|\bwurstplus\b/i, severity: 'critical' },
      { name: 'InertiaV2', regex: /\binertia\s*v\d+\b/i, severity: 'critical' },
      { name: 'Dankhack', regex: /\bdankhack\b/i, severity: 'critical' },
      { name: 'Zeroday', regex: /\bzeroday\s*(client|mod|hack)\b/i, severity: 'critical' },
      { name: 'Phobos', regex: /\bphobos\s*(client|mod|hack)\b/i, severity: 'critical' },
      { name: 'Novoline', regex: /\bnovoline\b/i, severity: 'critical' },
      { name: 'FlareOn', regex: /\bflareon\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'KonasClient', regex: /\bkonas\s*client\b|\bkonasclient\b/i, severity: 'critical' },
      { name: 'Prestige', regex: /\bprestige\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Xenon', regex: /\bxenon\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Argon', regex: /\bargon\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Hellion', regex: /\bhellion\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Virgin', regex: /\bvirgin\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Donut', regex: /\bdonut\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'VapeClient', regex: /\bvape\s*(client|v4|v3|v2|lite)?\b/i, severity: 'critical' },
      { name: 'MeteorClient', regex: /\bmeteor\s*client\b/i, severity: 'high' },
      { name: 'LiquidBounce', regex: /\bliquid\s*bounce\b/i, severity: 'high' },
      { name: 'RusherHack', regex: /\brusher\s*hack\b/i, severity: 'critical' },
      { name: 'FutureClient', regex: /\bfuture\s*client\b/i, severity: 'critical' },
      { name: 'Aristois', regex: /\baristois\b/i, severity: 'critical' },
      { name: 'Pandaware', regex: /\bpandaware\b/i, severity: 'critical' },
      { name: 'AstolfoClient', regex: /\bastolfo\s*client\b/i, severity: 'critical' },
      { name: 'NovoClient', regex: /\bnovo\s*client\b|\bnovoclient\b/i, severity: 'critical' },
      { name: 'IntentClient', regex: /\bintent\s*client\b|\bintentclient\b/i, severity: 'critical' },
      { name: 'Konas', regex: /\bkonas\b/i, severity: 'critical' },
      { name: 'SalHack', regex: /\bsal\s*hack\b|\bsalhack\b/i, severity: 'critical' },
      { name: 'Wurst', regex: /\bwurst\s*(client|mod|hack)\b/i, severity: 'high' },
      { name: 'Impact', regex: /\bimpact\s*(client|mod)\b/i, severity: 'high' },
      { name: 'Sigma', regex: /\bsigma\s*(client|mod)\b/i, severity: 'high' },
      { name: 'HackedClient', regex: /\bhacked\s*client\b|\bhc\s*client\b/i, severity: 'critical' },
      { name: 'Doyle', regex: /\bdoyle\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Praxis', regex: /\bpraxis\s*(client|mod)\b/i, severity: 'critical' },
      { name: 'Moonclient', regex: /\bmoon\s*client\b|\bmoonclient\b/i, severity: 'high' },
      { name: 'Inertia', regex: /\binertia\s*(client|mod)\b/i, severity: 'high' },
      { name: 'Ares', regex: /\bares\s*(client|mod)\b/i, severity: 'high' },
      { name: 'Tenacity', regex: /\btenacity\s*(client|mod)\b/i, severity: 'high' },
      { name: 'Dortware', regex: /\bdort\s*ware\b|\bdortware\b/i, severity: 'critical' },
    ]
  },

  obfuscation_signatures: {
    label: '🔒 Known Obfuscators',
    patterns: [
      { name: 'Skidfuscator', regex: /skidfuscator|skidfuscator/i, severity: 'critical' },
      { name: 'Paramorphism', regex: /paramorphism/i, severity: 'high' },
      { name: 'Radon', regex: /\bradon\b.*obfusc|obfusc.*\bradon\b/i, severity: 'medium' },
      { name: 'Caesium', regex: /\bcaesium\b.*obfusc|obfusc.*\bcaesium\b/i, severity: 'medium' },
      { name: 'Bozar', regex: /\bbozar\b/i, severity: 'medium' },
      { name: 'Branchlock', regex: /\bbranchlock\b/i, severity: 'medium' },
      { name: 'Binscure', regex: /\bbinscure\b/i, severity: 'medium' },
      { name: 'Qprotect', regex: /\bqprotect\b/i, severity: 'high' },
      { name: 'Zelix', regex: /\bzelix\b.*klass|klass.*\bzelix\b/i, severity: 'medium' },
      { name: 'Stringer', regex: /\bstringer\b/i, severity: 'medium' },
      { name: 'Allatori', regex: /\ballatori\b/i, severity: 'medium' },
      { name: 'ProGuard', regex: /\bproguard\b/i, severity: 'low' },
      { name: 'YGuard', regex: /\byguard\b/i, severity: 'low' },
      { name: 'Superblaubeere27', regex: /\bsuperblaubeere27\b/i, severity: 'high' },
      { name: 'Smoke', regex: /\bsmoke\s*(obfusc|protect)\b/i, severity: 'high' },
      { name: 'Scuti', regex: /\bscuti\s*(obfusc|protect)\b/i, severity: 'high' },
      { name: 'JNIC', regex: /\bjnic\b/i, severity: 'high' },
    ]
  },

  suspiciousStructural: {
    label: '⚠️ Suspicious Behavior',
    patterns: [
      { name: 'RuntimeExec', regex: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder|runtime.*exec/i, severity: 'critical' },
      { name: 'HttpClient', regex: /java\.net\.URL|HttpURLConnection|HttpClient|http.*request.*external/i, severity: 'high' },
      { name: 'FileWriteSensitive', regex: /User\\\\AppData\\\\Roaming\\\\(Microsoft\\\\Windows\\\\Start|discord|google.*chrome|mozilla|opera|brave)|\.minecraft\\\\(saves|versions|assets\\\\indexes)/i, severity: 'critical' },
      { name: 'NativeLoad', regex: /System\.loadLibrary|System\.load\b|Runtime.*load/i, severity: 'high' },
      { name: 'ReflectionAbuse', regex: /setAccessible\s*\(\s*true\s*\)|getDeclaredMethod|getDeclaredField/i, severity: 'high' },
      { name: 'DynamicClassLoader', regex: /URLClassLoader|ClassLoader.*define|ClassLoader.*loadClass/i, severity: 'high' },
      { name: 'ClassLoaderInherit', regex: /extends\s+ClassLoader|extends\s+URLClassLoader/i, severity: 'critical' },
      { name: 'ScriptEngine', regex: /ScriptEngine|javax\.script|Nashorn|Rhino.*eval/i, severity: 'critical' },
      { name: 'CipherEncrypt', regex: /javax\.crypto|Cipher.*encrypt|AES.*encrypt|encrypt.*password/i, severity: 'high' },
      { name: 'FileDelete', regex: /Files\.delete|\.delete\(\)|deleteOnExit/i, severity: 'low' },
      { name: 'HiddenFile', regex: /hidden\s*file|setHidden|setAttributes.*HIDDEN/i, severity: 'high' },
      { name: 'ClipboardAccess', regex: /java\.awt\.Clipboard|getSystemClipboard|Toolkit\.getDefault.*getSystemClipboard/i, severity: 'high' },
      { name: 'ProxyConnection', regex: /Proxy|proxy.*server|socks|SOCKS/i, severity: 'high' },
      { name: 'Base64Encode', regex: /Base64\.getEncoder|Base64\.encode|Base64.*decode.*getBytes/i, severity: 'medium' },
      { name: 'InetAddr', regex: /InetAddress\.getByName|InetAddress\.getLocalHost/i, severity: 'medium' },
      { name: 'ScheduledExecutor', regex: /ScheduledExecutorService|ScheduledThreadPool|scheduleAtFixedRate/i, severity: 'low' },
      { name: 'SelfDestruct', regex: /self\s*destruct|selfdestruct|delete.*self|remove.*evidence/i, severity: 'critical' },
      { name: 'DecompileGuard', regex: /anti\s*decompil|decompil.*detect|decompil.*guard|anti.*reverse/i, severity: 'high' },
      { name: 'VMCheck', regex: /vm.*detect|detect.*virtual|sandbox.*detect|vmware.*detect|vbox.*detect/i, severity: 'high' },
      { name: 'ClipboardWatch', regex: /clipboard.*listen|clipboard.*monitor|clipboard.*watch/i, severity: 'high' },
    ]
  },

  mixins: {
    label: '🔧 Suspicious Mixins',
    patterns: [
      { name: 'LicenseCheckMixin', regex: /LicenseCheck|licensecheck.*mixin/i, severity: 'critical' },
      { name: 'PlayerInteractionAccessor', regex: /PlayerInteractionManager.*Accessor|PlayerInteractionManager.*Mixin/i, severity: 'high' },
      { name: 'NetworkManagerMixin', regex: /NetworkManager.*Mixin|NetHandler.*Mixin/i, severity: 'high' },
      { name: 'ClientPlayerMixin', regex: /ClientPlayer.*Mixin|LocalPlayer.*Mixin/i, severity: 'medium' },
      { name: 'MixinConfig', regex: /mixin\.json|mixins\.json/i, severity: 'low' },
      { name: 'MixinExtras', regex: /mixinextras|@Inject|@Redirect|@ModifyVariable/i, severity: 'low' },
      { name: 'AccessTransformer', regex: /accesstransformer|accesswidener|AT\.CFG/i, severity: 'low' },
    ]
  },

  clientFiles: {
    label: '📂 Suspicious Files',
    patterns: [
      { name: 'PhantomRefmap', regex: /phantom.*refmap|cheat.*refmap|client.*refmap/i, severity: 'critical' },
      { name: 'NativeHook', regex: /jnativehook|JNativeHook|nativehook/i, severity: 'high' },
      { name: 'ImGuiBinding', regex: /imgui\.binding|imgui\.gl3|imgui\.glfw|imgui.*impl/i, severity: 'high' },
      { name: 'LWJGLHack', regex: /lwjgl.*input|lwjgl.*keyboard.*hook/i, severity: 'high' },
      { name: 'CheatConfig', regex: /cheat.*config|client.*config|hack.*config|module.*config/i, severity: 'high' },
      { name: 'ModuleSystem', regex: /module.*manager|module.*system|module.*registry/i, severity: 'high' },
      { name: 'ClickGui', regex: /click\s*gui|clickgui/i, severity: 'high' },
      { name: 'TabGui', regex: /tab\s*gui|tabgui/i, severity: 'high' },
      { name: 'ModuleCategory', regex: /module.*category|category.*combat|category.*movement|category.*render/i, severity: 'high' },
      { name: 'Settings', regex: /settings.*cheat|cheat.*settings|hack.*settings/i, severity: 'high' },
    ]
  },

  fullwidth: {
    label: '🔠 Fullwidth Unicode',
    patterns: [
      { name: 'FullwidthDetection', regex: /[\uFF21-\uFF3A\uFF41-\uFF5A]{2,}|[\u3000-\u303F]{2,}|\uFF10-\uFF19{2,}/, severity: 'critical' },
      { name: 'FullwidthCheat', regex: /[\uFF21-\uFF3A\uFF41-\uFF5A]+[\s\u3000-\u303F]*[\uFF21-\uFF3A\uFF41-\uFF5A]+/, severity: 'critical' },
      { name: 'FullwidthKillAura', regex: /[\uFF2B\uFF4B][\uFF29\uFF49][\uFF2C\uFF4C][\uFF2C\uFF4C].*[\uFF21\uFF41][\uFF35\uFF55][\uFF32\uFF52]/i, severity: 'critical' },
      { name: 'FullwidthAuto', regex: /[\uFF21\uFF41][\uFF35\uFF55][\uFF34\uFF54][\uFF2F\uFF4F]/i, severity: 'critical' },
      { name: 'FullwidthBypass', regex: /[\uFF22\uFF42][\uFF39\uFF59][\uFF30\uFF50][\uFF21\uFF41][\uFF33\uFF53][\uFF33\uFF53]/i, severity: 'critical' },
      { name: 'FullwidthSpeed', regex: /[\uFF33\uFF53][\uFF30\uFF50][\uFF25\uFF45][\uFF25\uFF45][\uFF24\uFF44]/i, severity: 'critical' },
      { name: 'FullwidthFly', regex: /[\uFF26\uFF46][\uFF2C\uFF4C][\uFF39\uFF59]/i, severity: 'critical' },
      { name: 'FullwidthKill', regex: /[\uFF2B\uFF4B][\uFF29\uFF49][\uFF2C\uFF4C][\uFF2C\uFF4C]/i, severity: 'critical' },
    ]
  },

  networkActivity: {
    label: '🌐 Network Activity',
    patterns: [
      { name: 'WebhookDiscord', regex: /discord\.com\/api\/webhooks|discordapp\.com\/api\/webhooks/i, severity: 'critical' },
      { name: 'C2Server', regex: /command.*and.*control|c2.*server|c2.*comm/i, severity: 'critical' },
      { name: 'DnsExfil', regex: /dns.*exfil|dns.*tunnel|dns.*channel/i, severity: 'critical' },
      { name: 'TorProxy', regex: /tor.*proxy|onion.*routing|\.onion/i, severity: 'high' },
      { name: 'PastebinFetch', regex: /pastebin\.com|rentry\.co|hastebin/i, severity: 'high' },
      { name: 'GithubRawContent', regex: /raw\.githubusercontent\.com|github\.com.*raw/i, severity: 'high' },
      { name: 'Ngrok', regex: /ngrok\.io|ngrok\.app|localtunnel/i, severity: 'high' },
      { name: 'TelegramBot', regex: /api\.telegram\.org|telegram.*bot.*api/i, severity: 'critical' },
      { name: 'MinehutProxy', regex: /minehut.*proxy|proxy.*minehut/i, severity: 'high' },
      { name: 'CustomServer', regex: /new\s*Socket\(|ServerSocket\(|InetAddress\.getByName/i, severity: 'high' },
    ]
  },

  dataExfil: {
    label: '📤 Data Exfiltration',
    patterns: [
      { name: 'HWID', regex: /hwid.*grab|hardware.*id.*collect|machine.*id/i, severity: 'critical' },
      { name: 'SystemInfo', regex: /SystemInfo|os\.name|os\.arch|user\.name.*collect/i, severity: 'high' },
      { name: 'ScreenCapture', regex: /screen.*capture|screenshot.*send|robot.*createScreenCapture/i, severity: 'critical' },
      { name: 'MicAccess', regex: /AudioFormat|TargetDataLine|AudioSystem.*getTargetDataLine/i, severity: 'critical' },
      { name: 'BrowserData', regex: /Chrome.*User.*Data|Firefox.*Profiles|Brave.*User.*Data/i, severity: 'critical' },
      { name: 'WifiPasswords', regex: /netsh.*wlan.*show.*profiles|wifi.*password|wlan.*key/i, severity: 'critical' },
      { name: 'CryptoAddress', regex: /Bitcoin.*address|Ethereum.*address|crypto.*wallet.*address/i, severity: 'critical' },
      { name: 'IPLogger', regex: /ip.*log|iplogger|ip.*track|ipinfo\.io|ipapi\.co/i, severity: 'high' },
      { name: 'StealSession', regex: /steal.*session|session.*theft|session.*grab/i, severity: 'critical' },
      { name: 'TokenSteal', regex: /token.*theft|grab.*token|token.*harvest/i, severity: 'critical' },
      { name: 'ScreenshotSteal', regex: /screenshot.*steal|steal.*screenshot|capture.*screen.*send/i, severity: 'critical' },
      { name: 'FileExfil', regex: /exfil.*file|steal.*file.*upload|file.*send.*server/i, severity: 'critical' },
    ]
  },

  persistence: {
    label: '♻️ Persistence & Evasion',
    patterns: [
      { name: 'StartupRegistry', regex: /HKEY.*\\Run|reg.*add.*\\run|startup.*folder|TaskScheduler.*register/i, severity: 'critical' },
      { name: 'WatchdogEvade', regex: /watchdog.*evade|evade.*watchdog|watchdog.*bypass.*packet/i, severity: 'critical' },
      { name: 'ModUnload', regex: /mod.*unload|unload.*mod|dynamic.*unloading/i, severity: 'high' },
      { name: 'SelfRemove', regex: /self.*remove|self.*delete|shred.*self|cleanup.*痕迹|delete.*trace/i, severity: 'critical' },
      { name: 'LogBypass', regex: /log.*bypass|bypass.*log|hide.*from.*log|log.*hide/i, severity: 'high' },
      { name: 'FakeModName', regex: /pretend.*to.*be|fake.*mod.*name|impersonate.*mod|disguise.*as/i, severity: 'high' },
      { name: 'TimeBomb', regex: /time.*bomb|delayed.*activate|scheduled.*activate|trigger.*after.*time/i, severity: 'critical' },
      { name: 'ConditionalPayload', regex: /if.*server.*online|if.*anti.*cheat.*detect|condition.*load.*payload/i, severity: 'critical' },
      { name: 'MinerDetection', regex: /mining.*rate.*hash|miner.*detect|coin.*miner|crypto.*miner/i, severity: 'critical' },
      { name: 'Ransomware', regex: /encrypt.*files.*decrypt|decrypt.*pay|ransom|bitcoin.*payment/i, severity: 'critical' },
      { name: 'Bootkit', regex: /bootkit|rootkit|kernel.*hook|driver.*inject/i, severity: 'critical' },
      { name: 'DNSOverwrite', regex: /dns.*overwrite|dns.*poison|dns.*redirect/i, severity: 'critical' },
      { name: 'HiddenService', regex: /hidden.*service|dark.*web|tor.*hidden|onion.*service/i, severity: 'critical' },
      { name: 'CodeSigning', regex: /forge.*signature|fake.*sign|code.*sign.*bypass/i, severity: 'critical' },
      { name: 'LoaderMod', regex: /mod.*loader.*inject|loader.*inject|inject.*via.*mod/i, severity: 'critical' },
    ]
  }
};

// Suspicious file names to look for inside JARs
const SUSPICIOUS_FILE_NAMES = [
  /hack/i, /cheat/i, /exploit/i, /cheat.*client/i, /bypass/i,
  /auto.*click/i, /kill.*aura/i, /aim.*assist/i, /velocity/i,
  /fly.*hack/i, /speed.*hack/i, /scaffold/i, /esp\.class/i,
  /click.*gui/i, /module/i, /client\.class/i,
];

// Known legitimate mods for false positive reduction
const KNOWN_LEGITIMATE_MODS = [
  'optifine', 'optifabric', 'lithium', 'sodium', 'iris', 'phosphor',
  'starlight', 'fabric-api', 'forge', 'neoforge', 'architectury',
  'cloth-config', 'modmenu', 'jei', 'jeiintegration', 'hwyla', 'waila',
  'journeymap', 'xaeros-minimap', 'rei', 'emi', 'appleskin', 'itemscroller',
  'worldedit', 'worldguard', 'buildcraft', 'industrialcraft', 'mekanism',
  'thermal', 'tinker', 'botania', 'thaumcraft', 'computercraft',
  'wireless-redstone', 'not-enough-items', 'roughly-enough-items',
  'create', 'create-fabric', 'create-mechanical', 'immersive-engineering',
  'twilight-forest', 'biomes-o-plenty', 'oh-the-biomes-youll-go',
  'shaders-mod', 'optishine', 'canvas-renderer', 'rubidium',
];

// Suspicious download sources
const SUSPICIOUS_SOURCES = [
  'discord.com', 'discord.gg', 'discordapp.com',
  'mediafire.com', 'mega.nz', 'mega.co.nz',
  'dropbox.com', 'drive.google.com',
  'anydesk.com',
];

const SAFE_SOURCES = [
  'modrinth.com', 'curseforge.com',
];

module.exports = {
  CHEAT_PATTERNS,
  SUSPICIOUS_FILE_NAMES,
  KNOWN_LEGITIMATE_MODS,
  SUSPICIOUS_SOURCES,
  SAFE_SOURCES
};
