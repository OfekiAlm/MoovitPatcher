# MoovitPatcher: Android Vulnerability Research & Exploitation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Android Security Model & Attack Surface](#android-security-model--attack-surface)
3. [Vulnerability Research Methodology](#vulnerability-research-methodology)
4. [Discovered Vulnerabilities](#discovered-vulnerabilities)
5. [Technical Implementation](#technical-implementation)
6. [Architecture & Design Decisions](#architecture--design-decisions)
7. [Exploitation Workflow](#exploitation-workflow)
8. [Tools & Technologies](#tools--technologies)
9. [Security Considerations](#security-considerations)

---

## Project Overview

**MoovitPatcher** is a proof-of-concept Android application patcher that demonstrates vulnerabilities in the Moovit transit application's client-side subscription validation and advertisement display logic. The project showcases how Android applications that implement security-sensitive checks on the client side can be bypassed through runtime code injection and method hooking.

### Primary Goals
- Demonstrate weaknesses in client-side validation mechanisms
- Bypass premium subscription checks to access paid features
- Remove advertisements from the application
- Enable live location features without legitimate subscription

### Research Context
This project explores the broader Android security principle: **never trust the client**. It demonstrates why critical business logic and validation should always be implemented server-side, as client-side code can be modified, reverse-engineered, and manipulated at runtime.

---

## Android Security Model & Attack Surface

### Android Application Architecture
Android applications (APKs) are packaged as ZIP archives containing:
- **DEX files**: Dalvik Executable format containing compiled Java/Kotlin bytecode
- **Resources**: Images, strings, layouts, and other assets
- **AndroidManifest.xml**: Application metadata, permissions, and component declarations
- **Native libraries**: Compiled C/C++ code (`.so` files) for different CPU architectures
- **Signature**: Digital signature verifying application authenticity

### Relevant Android Security Mechanisms

#### 1. Application Signing
- Every APK must be digitally signed with a certificate
- Android verifies signature integrity at installation time
- **Vulnerability**: After initial verification, Android does not re-verify code at runtime
- **Implication**: Modified and re-signed APKs can be installed if users accept the new certificate

#### 2. Code Obfuscation
- Developers use ProGuard/R8 to obfuscate code, making reverse engineering harder
- Renames classes, methods, and fields to meaningless names
- **Vulnerability**: Obfuscation is security-through-obscurity; it slows but doesn't prevent analysis
- **Bypass**: Pattern matching on behavior rather than names reveals target methods

#### 3. Client-Side Validation
- Many apps implement subscription/premium feature checks in client code
- **Vulnerability**: All client-side checks can be bypassed by an attacker with device control
- **Attack Vector**: Runtime method hooking, code injection, or smali modification

#### 4. Application Sandboxing
- Each app runs in its own process with unique UID
- **Limitation**: Sandbox doesn't prevent self-modification on rooted devices or modified APKs
- **Context**: This project modifies APK before installation, bypassing runtime protections

### Attack Surface Analysis

For the Moovit application, the attack surface includes:

1. **Subscription Validation Logic**
   - Location: Client-side Java/Kotlin code
   - Method signature: `()Z` (returns boolean)
   - Weakness: Decision made entirely in client code

2. **Advertisement Display Components**
   - Activity lifecycle integration
   - Can be intercepted at entry points (onCreate, onResume)

3. **API Key Validation**
   - Google Maps API key stored in resources
   - Can be replaced with custom key for tracking/control

4. **Entry Points**
   - Activities marked as `exported="true"`
   - All activities, services, receivers, and providers are potential injection points

---

## Vulnerability Research Methodology

### Phase 1: Static Analysis

#### Step 1: APK Extraction and Decompilation
```bash
# Extract APK structure
unzip moovit.apk -d extracted/

# Decompile to smali (assembly-like representation)
apktool d moovit.apk -o decompiled/
```

**Tools Used:**
- **apktool**: Decompiles APK to smali and resources
- Reveals AndroidManifest.xml, resources, and disassembled bytecode

#### Step 2: Identify Target Classes
The research looked for patterns indicating subscription validation:

```python
# Pattern search in subscription_manager.py
IS_SUBSCRIBED_RE = re.compile(
    r'.method public final (?P<method_name>\w+)(?P<sig>\(\)Z)(?:(?!end method)[\s\S])*?booleanValue'
)
```

**Key Discovery Pattern:**
- Method returns boolean (`()Z` signature)
- Contains string constant `"subscribed_skus"` 
- Calls `booleanValue` on a result (likely checking subscription status)

**Reasoning:**
- Subscription checks must ultimately return true/false
- String "subscribed_skus" strongly indicates IAP (In-App Purchase) logic
- Pattern matching allows finding obfuscated methods by behavior, not name

#### Step 3: String-Based Artifact Discovery
```python
def class_filter(self, class_data: str) -> bool:
    return '"subscribed_skus"' in class_data
```

**Strategy:**
- Search all `.smali` files for key strings
- String literals survive obfuscation (though they can be encrypted)
- "subscribed_skus" is a strong indicator of subscription management code

**What This Reveals:**
- The target class manages subscription state
- The class likely queries Google Play Billing API for subscription info
- The boolean method represents the critical validation point

### Phase 2: Dynamic Analysis Considerations

While this project uses static patching, typical research would include:
- **Logging**: Insert log statements to observe runtime behavior
- **Debugging**: Attach debugger to observe method calls and returns
- **Network Analysis**: Intercept API calls to understand server communication

**Why Static Patching Was Chosen:**
- No root access required on target device
- Works on any device accepting modified APK
- Permanent modification, no runtime hooks needed
- Demonstrates fundamental APK modification techniques

### Phase 3: Vulnerability Validation

#### Hypothesis
"If the subscription check is client-side, replacing the boolean-returning method to always return `true` will grant premium access."

#### Testing Approach
1. Locate method through pattern matching
2. Hook method using YAHFA framework
3. Replace implementation to always return `true`
4. Inject hook at application entry points
5. Test premium features

---

## Discovered Vulnerabilities

### Vulnerability 1: Client-Side Subscription Validation

**CVE Classification**: Logic flaw, insufficient server-side validation

**Technical Details:**
- **Location**: Subscription manager class (obfuscated name)
- **Method Signature**: `()Z` (public method, no parameters, returns boolean)
- **Vulnerability**: Subscription status determined entirely by client method return value

**Root Cause:**
```java
// Vulnerable pattern (reconstructed from smali)
public boolean isSubscribed() {
    // Query local state or cached subscription info
    Set<String> subscribedSkus = getSubscribedSkus();
    return !subscribedSkus.isEmpty();
}
```

**Why This Is Vulnerable:**
1. **Local State**: Decision based on device-stored data
2. **No Server Verification**: No real-time check with payment provider
3. **Client Control**: Return value controlled by client-side code
4. **Caching Trust**: Trusts cached subscription state without expiry verification

**Exploitation:**
```java
// Hook replacement (SubscriptionManager.java)
static boolean is_subscribed(Object self) {
    return true;  // Always return subscribed status
}
```

**Impact:**
- Unlimited access to premium features without payment
- Live location tracking enabled
- Premium trip planning features unlocked
- Ad-free experience

**Proper Mitigation:**
```java
// Secure approach
public boolean isSubscribed() {
    // 1. Check server-side subscription status in real-time
    // 2. Use secure, signed tokens from server
    // 3. Implement certificate pinning to prevent MITM
    // 4. Add integrity checks to detect tampering
    // 5. Implement server-side feature gating
    return verifySubscriptionWithServer();
}
```

### Vulnerability 2: Exposed Application Entry Points

**Technical Details:**
- **Location**: AndroidManifest.xml exported components
- **Affected Components**: Activities, Services, Receivers, Providers

**Discovery:**
```python
def get_activities_with_entry_points(apk_path: Path) -> list:
    manifest = APK(str(apk_path)).get_android_manifest_xml()
    activities = []
    for element in manifest.find('.//application').getchildren():
        should_patch = False
        if element.tag == 'activity' or element.tag == 'activity-alias':
            should_patch = element.get(ManifestKeys.EXPORTED) == 'true'
        elif element.tag == 'provider' or element.tag == 'receiver' or element.tag == 'service':
            should_patch = True  # Implicit entry points
        if should_patch:
            activities.append(element)
    return activities
```

**Vulnerability:**
- Each entry point provides injection opportunity
- No integrity checks on early initialization
- onCreate/onInit methods execute before main application logic

**Exploitation:**
- Inject hook loader at every entry point
- Ensures hook runs regardless of app launch path
- Maximizes hook reliability across app states

### Vulnerability 3: Hardcoded API Keys

**Technical Details:**
- **Location**: `resources.arsc` (compiled resources)
- **Resource Name**: `google_api_key`
- **Vulnerability**: Static key embedded in APK

**Discovery:**
```python
def patch_google_api_key(temp_path: Path, package_name: str, custom_google_api_key: str):
    resources_path = temp_path / EXTRACTED_PATH / 'resources.arsc'
    resources = ARSCParser(resources_path.read_bytes())
    _, original_google_api_key = resources.get_string(package_name, 'google_api_key')
    with open(resources_path, 'rb') as file:
        resources_data = file.read()
    resources_data = resources_data.replace(
        original_google_api_key.encode(), 
        custom_google_api_key.encode()
    )
    with open(resources_path, 'wb') as file:
        file.write(resources_data)
```

**Impact:**
- Key can be extracted and reused
- Usage tracking attribution issues
- Quota abuse potential
- No runtime validation

**Proper Mitigation:**
- Request API keys from backend at runtime
- Implement key rotation
- Use Firebase Remote Config for dynamic keys
- Add usage analytics and abuse detection

---

## Technical Implementation

### Component Architecture

```
MoovitPatcher/
├── main.py                      # Orchestration: extract, patch, compile, sign
├── artifactory.py               # Artifact preparation/caching
├── artifactory_generator/       # Pattern-based code discovery
│   ├── SimpleArtifactoryFinder.py    # Base class for artifact extraction
│   ├── generate_artifactory.py       # Orchestrates artifact discovery
│   └── artifactory_types/
│       └── subscription_manager.py   # Finds subscription validation method
├── smali_generator/             # Java/native code to inject
│   ├── app/                     # Hooking infrastructure
│   │   └── src/main/java/com/smali_generator/
│   │       ├── TheAmazingPatch.java  # Hook initialization
│   │       ├── Hook.java             # Hook interface
│   │       └── patches/
│   │           └── SubscriptionManager.java  # Subscription bypass hook
│   └── library/                 # YAHFA hooking framework (C/Java)
│       └── src/main/java/lab/galaxy/yahfa/
│           └── HookMain.java    # JNI bridge to ART hooking
└── ultimate_patcher/            # APK manipulation utilities
    ├── apk_utils.py             # Extract, compile, sign operations
    ├── patcher.py               # Core patching logic
    └── common.py                # Constants and configurations
```

### Step-by-Step Exploitation Workflow

#### 1. APK Extraction
```python
def extract_apk(apk_path: os.PathLike, temp_path: Path):
    subprocess.check_call([
        "java", "-jar", APKTOOL_PATH,
        "d", "-q", "-r",  # decode, quiet, no resource decoding
        "--output", temp_path / EXTRACTED_PATH,
        apk_path,
    ])
```

**What Happens:**
- APK (ZIP) is decompressed
- DEX files converted to smali (human-readable assembly)
- Resources extracted (AndroidManifest.xml, images, strings)
- Directory structure mirrors APK internal structure

**Why `-r` flag (skip resources):**
- Faster extraction when only code patching needed
- Avoids resource decompilation errors
- Resources can still be modified as binary

#### 2. Artifact Discovery (Target Identification)

**Process:**
```python
def generate_artifactory(args):
    artifacts = dict()
    simple_artifacts_to_find = [
        SubscriptionManager(args),
    ]
    for filename in glob.iglob(os.path.join(args.temp_path, config.EXTRACTED_TEMP_DIR, "**", "*.smali"), recursive=True):
        with open(filename, "r", encoding="utf8") as f:
            data = f.read()
        for artifact_finder in simple_artifacts_to_find:
            if not artifact_finder.class_filter(data):
                continue
            artifact_finder.extract_artifacts(artifacts, data)
```

**Subscription Manager Discovery:**
```python
# Pattern: boolean method that checks subscription
IS_SUBSCRIBED_RE = re.compile(
    r'.method public final (?P<method_name>\w+)(?P<sig>\(\)Z)(?:(?!end method)[\s\S])*?booleanValue'
)

def extract_artifacts(self, artifacts: dict, class_data: str) -> None:
    matches = list(self.IS_SUBSCRIBED_RE.finditer(class_data))
    if len(matches) != 1:  # Expect exactly one match for reliability
        return
    artifacts['SUBSCRIPTION_MANAGER_CLASS_NAME'] = CLASS_NAME_RE.match(class_data).groupdict()['name'].replace('/', '.')
    artifacts['SUBSCRIPTION_MANAGER_METHOD_NAME'] = matches[0].groupdict()['method_name']
    artifacts['SUBSCRIPTION_MANAGER_METHOD_SIG'] = matches[0].groupdict()['sig']
```

**Output Example:**
```json
{
    "SUBSCRIPTION_MANAGER_CLASS_NAME": "com.moovit.app.billing.SubscriptionManager",
    "SUBSCRIPTION_MANAGER_METHOD_NAME": "a",
    "SUBSCRIPTION_MANAGER_METHOD_SIG": "()Z"
}
```

**Key Insights:**
- Method name is obfuscated (`a`) but signature reveals behavior
- `()Z` = no parameters, returns boolean
- Pattern matching on behavior, not names, defeats obfuscation
- Template system allows dynamic hook generation

#### 3. Hook Code Generation

**Template System:**
```java
// SubscriptionManager.java template
public class SubscriptionManager implements Hook {
    static boolean is_subscribed(Object self) {
        return true;  // Bypass: always subscribed
    }

    public void load() {
        Log.i("PATCH", "SubscriptionManager: Patch loaded");
        try {
            Class<?> subscription_manager_class = Class.forName("{{SUBSCRIPTION_MANAGER_CLASS_NAME}}");
            Method is_subscribed_hook = SubscriptionManager.class.getDeclaredMethod("is_subscribed", Object.class);
            Method original_is_subscribed = subscription_manager_class.getDeclaredMethod("{{SUBSCRIPTION_MANAGER_METHOD_NAME}}");
            HookMain.hook(original_is_subscribed, is_subscribed_hook);
        } catch (Exception e) {
            Log.e("PATCH", "SubscriptionManager: " + e.toString());
        }
    }
}
```

**Templating Process:**
```python
def patch_artifacts(artifactory: Path, smali_generator_temp_path: Path):
    with open(artifactory, 'r') as file:
        artifactory = json.load(file)
    for file in glob.iglob(str(smali_generator_temp_path / '**' / '**'), recursive=True):
        with open(file, 'rb') as f:
            old_data = f.read()
        data = old_data
        for key, value in artifactory.items():
            data = data.replace(f'{{{{{key}}}}}'.encode(), value.encode())
        with open(file, 'wb') as f:
            f.write(data)
```

**Result:**
```java
// After templating
Class<?> subscription_manager_class = Class.forName("com.moovit.app.billing.SubscriptionManager");
Method original_is_subscribed = subscription_manager_class.getDeclaredMethod("a");
```

#### 4. Hook Compilation

**Build Process:**
```python
def prepare_smali(temp_path: Path, artifactory: Path, external_module: Path):
    # Copy smali_generator project to temp
    shutil.copytree(external_module, temp_path / SMALI_GENERATOR_TEMP_PATH)
    
    # Apply discovered artifacts via templating
    patch_artifacts(artifactory, temp_path / SMALI_GENERATOR_TEMP_PATH)
    
    # Compile Java → DEX → smali
    subprocess.check_call(['./gradlew', 'assembleRelease'], cwd=temp_path / SMALI_GENERATOR_TEMP_PATH)
    
    # Extract smali from compiled APK
    extract_apk(
        temp_path / SMALI_GENERATOR_TEMP_PATH / SMALI_GENERATOR_OUTPUT_PATH,
        temp_path,
        temp_path / SMALI_GENERATOR_TEMP_PATH / SMALI_EXTRACTED_PATH
    )
```

**Why This Flow:**
1. **Java → DEX**: Easier to write hooks in Java than smali
2. **DEX → smali**: Need smali to merge with target APK
3. **Gradle**: Handles compilation, dependencies, native library packaging
4. **Extract**: Re-decompile our own hook APK to get smali + .so files

#### 5. Smali Injection

**Smart Folder Management:**
```python
def get_new_smali_folder(smali_path: Path) -> Path:
    smali_folders = [folder for folder in smali_path.iterdir() 
                     if folder.is_dir() and folder.name.startswith('smali_classes')]
    if not smali_folders:
        return smali_path / 'smali'
    
    # Find highest smali_classes number
    smali_folders.sort(key=lambda x: int(x.name.replace('smali_classes', '')))
    smali_index = int(smali_folders[-1].name.replace('smali_classes', '')) + 1
    
    # Create new folder for our code
    (smali_path / f'smali_classes{smali_index}').mkdir()
    return smali_path / f'smali_classes{smali_index}'
```

**Why Multiple Smali Folders:**
- Android DEX limit: 65,536 methods per DEX file
- Large apps split into multiple DEX (multidex)
- Each smali_classesN becomes a separate classesN.dex
- Adding new folder = new DEX = no method limit conflicts

**Code Injection:**
```python
# Copy our hook code into new smali folder
shutil.copytree(
    temp_path / SMALI_GENERATOR_TEMP_PATH / SMALI_EXTRACTED_PATH / 'smali',
    new_smali_folder,
    dirs_exist_ok=True
)

# Move package folders to ensure proper DEX splitting
for folder in smali_folders:
    for file in folder.iterdir():
        if not (new_smali_folder / file.name).exists():
            shutil.move(file, new_smali_folder)
            break
```

#### 6. Native Library Injection

**Architecture-Specific Libraries:**
```python
# YAHFA native hooking library
os.makedirs(temp_path / EXTRACTED_PATH / 'lib' / arch, exist_ok=True)
shutil.copytree(
    temp_path / SMALI_GENERATOR_TEMP_PATH / SMALI_EXTRACTED_PATH / 'lib' / arch,
    temp_path / EXTRACTED_PATH / 'lib' / arch,
    dirs_exist_ok=True
)
```

**Native Library: libyahfa.so**
- **Purpose**: Low-level ART (Android Runtime) method hooking
- **Function**: Modifies ART's internal method structures at runtime
- **Why Native**: Java reflection cannot modify compiled method entry points

**Architecture Handling:**
```bash
lib/
├── arm64-v8a/
│   └── libyahfa.so    # 64-bit ARM (modern phones)
├── armeabi-v7a/
│   └── libyahfa.so    # 32-bit ARM (older phones)
├── x86/
│   └── libyahfa.so    # 32-bit Intel (emulators)
└── x86_64/
    └── libyahfa.so    # 64-bit Intel (emulators)
```

**Why Architecture Matters:**
- APK must contain native library for device CPU
- Wrong architecture = UnsatisfiedLinkError at runtime
- Project supports all common Android architectures

#### 7. Entry Point Hooking

**Strategy:**
```python
def patch_entries(apk_path: Path, temp_path: Path):
    activities_to_patch = get_activities_with_entry_points(apk_path)
    for activity in activities_to_patch:
        add_static_call_to_on_load(
            temp_path,
            activity.get(ManifestKeys.NAME),
            'onCreate' if 'activity' in activity.tag else '<init>'
        )
```

**Smali Injection:**
```python
INVOKE_LINE = '\n\tinvoke-static {}, Lcom/smali_generator/TheAmazingPatch;->on_load()V\n\t'

def patch_or_add_function(smali_file_path: Path, function_name: str):
    with open(smali_file_path, 'r') as file:
        smali_file = file.read()
    
    # Find all methods matching function_name (onCreate, onResume, etc.)
    matches = re.findall(fr'\.method \w+ [^\n]*{function_name}[^\n]*\n[^\n]+', smali_file)
    
    for match in matches:
        # Inject hook call at start of method
        smali_file = smali_file.replace(match, match + INVOKE_LINE)
    
    with open(smali_file_path, 'w') as file:
        file.write(smali_file)
```

**Before Injection (smali):**
```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
    # rest of method
.end method
```

**After Injection (smali):**
```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2
    invoke-static {}, Lcom/smali_generator/TheAmazingPatch;->on_load()V
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
    # rest of method
.end method
```

**Why This Works:**
- Hook initializer called before any app logic
- Static call = no object instance needed
- Idempotent: `AtomicBoolean` prevents double-initialization

**Hook Initialization:**
```java
public class TheAmazingPatch {
    static Hook[] hooks = {
        new SubscriptionManager(),
    };
    
    static AtomicBoolean is_loaded = new AtomicBoolean(false);
    
    public static void on_load() {
        if (is_loaded.getAndSet(true)) {
            return;  // Already loaded, skip
        }
        
        Log.e("PATCH", "Patch loaded!");
        try {
            for (Hook hook : hooks) {
                hook.load();  // Install each hook
            }
        } catch (Exception e) {
            Log.e("PATCH", "Error: " + e.getMessage());
        }
    }
}
```

#### 8. APK Recompilation

**Smali → DEX:**
```python
def compile_apk(input_path: Path, output_path: Path):
    # Ensure .so files aren't compressed (required for native libs)
    yml_path = input_path / 'apktool.yml'
    if yml_path.exists():
        with open(yml_path, 'r') as file:
            apktool_yml = yaml.safe_load(file)
        if 'so' not in apktool_yml['doNotCompress']:
            apktool_yml['doNotCompress'].append('so')
        with open(yml_path, 'w') as file:
            yaml.safe_dump(apktool_yml, file)
    
    subprocess.check_call([
        "java", "-jar", APKTOOL_PATH,
        "build", "-q",
        str(input_path),
        "--output", str(output_path)
    ])
```

**Critical Detail: SO Compression**
- Android cannot load compressed native libraries
- `doNotCompress: ['so']` prevents ZIP compression
- Without this, `System.loadLibrary("yahfa")` fails

#### 9. APK Signing

**Why Signing:**
- Android refuses to install unsigned APKs
- Signature verification at install time only
- Replacing signature = user must accept new certificate

**Signing Process:**
```python
def sign_apk(temp_path: Path, original_apk_path: Path, apk_path: Path, output_path: Path):
    args = ["java", "-jar", UBER_APK_SIGNER_PATH]
    
    # Use custom keystore if provided, else debug key
    if os.environ.get('KEYSTORE_PATH'):
        args.extend(["--ks", os.environ['KEYSTORE_PATH']])
        args.extend(["--ksAlias", os.environ['KEY_ALIAS']])
        args.extend(["--ksPass", os.environ['KEYSTORE_PASSWORD']])
        args.extend(["--ksKeyPass", os.environ['KEY_PASSWORD']])
    
    args.extend(['--allowResign', '--apks', apk_path])
    subprocess.check_call(args)
```

**Signature Implications:**
- Different signature = different app identity to Android
- Cannot update over original app (different cert)
- Loses access to original app's data
- Some features (Google Sign-In) may break due to cert mismatch

---

## Architecture & Design Decisions

### 1. Why YAHFA Over Other Hooking Frameworks?

**Alternatives Considered:**
- **Frida**: Requires root or debuggable APK, runtime-only
- **Xposed**: Requires rooted device with custom framework
- **LSPosed**: Modern Xposed, still requires root
- **Substrate**: Commercial, older, limited support

**Why YAHFA:**
- **No Root Required**: Hooks embedded in APK itself
- **Native Performance**: C-level ART manipulation
- **Persistent**: Works after device reboot
- **Modern**: Supports Android 7-14
- **Open Source**: Auditable, MIT licensed

### 2. Static Patching vs. Dynamic Hooking

**Static Patching Approach (Chosen):**
```
APK → Decompile → Modify → Recompile → Re-sign → Install
```

**Advantages:**
- ✅ No root required
- ✅ Permanent modification
- ✅ Works on any Android version
- ✅ User-friendly (just install APK)
- ✅ No runtime dependencies

**Disadvantages:**
- ❌ Requires re-signing (breaks updates)
- ❌ App-specific (must re-patch updates)
- ❌ Larger attack surface for detection

**Dynamic Hooking (Alternative):**
```
App runs → Frida attaches → Inject hooks → Runtime modification
```

**Advantages:**
- ✅ Doesn't modify APK
- ✅ Can hook/unhook live
- ✅ Useful for research/debugging

**Disadvantages:**
- ❌ Requires root or debuggable app
- ❌ Must attach every app launch
- ❌ Easily detectable (process inspection)

**Decision Rationale:**
For a user-facing tool that removes ads and enables features, static patching provides better UX without requiring technical knowledge or root access.

### 3. Template-Based Hook Generation

**Problem:**
- Target class/method names change with every app update (obfuscation)
- Hardcoding names would break immediately

**Solution:**
```python
# Discover at patch-time
artifacts = {
    "SUBSCRIPTION_MANAGER_CLASS_NAME": "com.moovit.a.b.c",
    "SUBSCRIPTION_MANAGER_METHOD_NAME": "a",
}

# Apply to template
hook_code = hook_template.replace("{{SUBSCRIPTION_MANAGER_CLASS_NAME}}", artifacts["..."])
```

**Benefits:**
- ✅ Resilient to obfuscation name changes
- ✅ Automatic adaptation to new versions
- ✅ Extensible pattern library
- ✅ Clear separation: discovery vs. exploitation

### 4. Entry Point Injection Strategy

**Challenge:**
Where to initialize hooks to guarantee execution?

**Approach 1: Application.onCreate (Rejected)**
```java
public class MyApplication extends Application {
    @Override
    public void onCreate() {
        // Hook here?
    }
}
```
- **Issue**: App may not have custom Application class
- **Issue**: Replacing Application class is fragile

**Approach 2: MainActivity.onCreate (Rejected)**
```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Hook here?
    }
}
```
- **Issue**: User might not launch via main activity
- **Issue**: Deep links, notifications bypass MainActivity

**Approach 3: All Entry Points (Chosen)**
```python
# Patch EVERY exported component
for activity in activities_to_patch:
    inject_hook_call(activity)
```
- ✅ Hooks regardless of app launch path
- ✅ Handles push notifications, deep links, widgets
- ✅ Redundant but reliable
- ✅ Idempotent initialization prevents overhead

### 5. Why Smali Instead of Direct DEX Modification?

**Smali (Human-Readable Assembly):**
```smali
.method public onCreate(Landroid/os/Bundle;)V
    invoke-static {}, Lcom/smali_generator/TheAmazingPatch;->on_load()V
    return-void
.end method
```

**Direct DEX (Binary):**
```
00 01 12 34 56 78 9A BC ...
```

**Advantages of Smali:**
- ✅ Human-readable, verifiable
- ✅ Text-based diffing and version control
- ✅ Regex-based pattern matching
- ✅ Easier debugging when patches fail
- ✅ apktool handles DEX ↔ smali conversion

**Why Not Bytecode Libraries (Javassist, ASM, etc.):**
- Java bytecode ≠ DEX bytecode
- Libraries designed for JVM, not Dalvik/ART
- Would need DEX-specific manipulation library

### 6. Bundle vs. APK Support

**Android App Bundle (.aab):**
- Google Play's modern distribution format
- Contains base.apk + feature splits + configuration splits
- Dynamic delivery: device downloads only needed resources

**Implementation:**
```python
def is_bundle(path: os.PathLike) -> bool:
    with zipfile.ZipFile(path, 'r') as zip_file:
        for file in zip_file.namelist():
            if file.endswith('.apk'):
                return True  # Bundle contains nested APKs
    return False

def extract_apk(apk_path, temp_path):
    if is_bundle(apk_path):
        # Extract all split APKs
        zip_file.extractall(temp_path / BUNDLE_APK_EXTRACTED_PATH)
        
        # Patch base.apk (contains main code)
        extract_apk(temp_path / BUNDLE_APK_EXTRACTED_PATH / 'base.apk', temp_path)
        
        # Keep splits for reassembly
        for apk_file in glob.iglob(str(temp_path / BUNDLE_APK_EXTRACTED_PATH / '*.apk')):
            if os.path.basename(apk_file) != 'base.apk':
                shutil.copy(apk_file, './bundle_apks')
```

**Why Patch Only base.apk:**
- Main application code lives in base.apk
- Splits contain resources, language packs, ABIs
- Subscription logic guaranteed in base.apk
- Other splits can be passed through unmodified

### 7. Architecture Selection

**Supported Architectures:**
```python
parser.add_argument('--arch', choices=['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'])
```

**Market Share (Approximate):**
- arm64-v8a: ~90% (all modern phones, 2015+)
- armeabi-v7a: ~8% (older phones, 2011-2015)
- x86/x86_64: ~2% (emulators, ChromeOS)

*Note: Based on Android Device Catalog and Google Play Console statistics. Actual distribution varies by region and target audience.*

**Decision:**
- Default: arm64-v8a (covers most users)
- Include libyahfa.so only for selected architecture
- Reduces APK size (native libs are large)

---

## Exploitation Workflow

### Complete Flow Diagram

```
┌─────────────────┐
│   Moovit APK    │
│   (Original)    │
└────────┬────────┘
         │
         ├── 1. EXTRACT (apktool d)
         │
         ▼
┌─────────────────────────────┐
│  Decompiled Structure       │
│  ├── smali/                 │
│  ├── smali_classes2/        │
│  ├── AndroidManifest.xml    │
│  ├── resources.arsc         │
│  └── lib/                   │
└────────┬────────────────────┘
         │
         ├── 2. DISCOVER ARTIFACTS
         │    (Pattern Matching)
         ▼
┌─────────────────────────────┐
│  Artifactory (JSON)         │
│  {                          │
│    "SUB_CLASS": "a.b.c",    │
│    "SUB_METHOD": "a",       │
│    "SUB_SIG": "()Z"         │
│  }                          │
└────────┬────────────────────┘
         │
         ├── 3. GENERATE HOOKS
         │    (Template → Java)
         ▼
┌─────────────────────────────┐
│  Hook Code (Java)           │
│  class SubscriptionManager  │
│    static bool hooked() {   │
│      return true;           │
│    }                        │
└────────┬────────────────────┘
         │
         ├── 4. COMPILE HOOKS
         │    (Gradle → APK)
         ▼
┌─────────────────────────────┐
│  Hook APK                   │
│  ├── classes.dex            │
│  └── lib/libyahfa.so        │
└────────┬────────────────────┘
         │
         ├── 5. EXTRACT HOOK SMALI
         │    (apktool d hook.apk)
         ▼
┌─────────────────────────────┐
│  Hook Smali + Native Lib    │
│  ├── smali/com/smali_gen/   │
│  └── lib/arm64-v8a/         │
└────────┬────────────────────┘
         │
         ├── 6. INJECT INTO TARGET
         │    ├── Copy smali → smali_classes8/
         │    ├── Copy .so → lib/arm64-v8a/
         │    └── Inject on_load() calls
         ▼
┌─────────────────────────────┐
│  Modified APK Structure     │
│  ├── smali_classes8/        │ ← Our hooks
│  │   └── com/smali_gen/     │
│  ├── lib/arm64-v8a/         │
│  │   └── libyahfa.so        │ ← Hook engine
│  └── Activities patched      │ ← Entry points
└────────┬────────────────────┘
         │
         ├── 7. RECOMPILE
         │    (apktool b)
         ▼
┌─────────────────────────────┐
│  Patched APK (Unsigned)     │
└────────┬────────────────────┘
         │
         ├── 8. SIGN
         │    (uber-apk-signer)
         ▼
┌─────────────────────────────┐
│  Patched APK (Signed)       │
│  Ready to Install           │
└────────┬────────────────────┘
         │
         ├── 9. INSTALL
         │    (adb install)
         ▼
┌─────────────────────────────┐
│  Modified Moovit Running    │
│  on Android Device          │
└─────────────────────────────┘
```

### Runtime Hook Execution

```
App Launch
    │
    ├── Android creates process
    │
    ├── Loads DEX files
    │   ├── classes.dex
    │   ├── classes2.dex
    │   └── classes8.dex ← Our hooks
    │
    ├── Loads native libraries
    │   └── libyahfa.so ← Hook engine
    │
    ├── Calls Activity.onCreate()
    │
    ├── → OUR INJECTED CODE
    │   └── TheAmazingPatch.on_load()
    │       │
    │       ├── Load YAHFA native library
    │       │   System.loadLibrary("yahfa")
    │       │
    │       ├── Initialize hooks
    │       │   SubscriptionManager.load()
    │       │       │
    │       │       ├── Reflect target class
    │       │       │   Class.forName("com.moovit.billing.a")
    │       │       │
    │       │       ├── Reflect target method
    │       │       │   class.getDeclaredMethod("a")
    │       │       │
    │       │       ├── Call YAHFA hook
    │       │       │   HookMain.hook(originalMethod, hookMethod)
    │       │       │       │
    │       │       │       └── JNI → Native Code
    │       │       │           └── Modify ART Method Structure
    │       │       │               ├── Save original entry point
    │       │       │               └── Replace with hook entry point
    │       │       │
    │       │       └── Return (hook installed)
    │       │
    │       └── Return (all hooks active)
    │
    ├── Continue normal app execution
    │
    └── When subscription check happens:
        │
        ├── App calls isSubscribed()
        │
        ├── ART routes to HOOK instead of original
        │
        ├── → SubscriptionManager.is_subscribed()
        │   └── return true;  ← Bypass
        │
        └── App grants premium access
```

---

## Tools & Technologies

### Core Technologies

#### 1. **apktool** (APK Decompilation/Recompilation)
- **Version**: 2.12.1
- **Purpose**: DEX ↔ smali conversion, resource extraction
- **Language**: Java
- **Alternatives**: jadx (decompiles to Java, not smali)

**Key Operations:**
```bash
# Decompile
apktool d input.apk -o output_dir/

# Recompile
apktool b output_dir/ -o patched.apk
```

#### 2. **uber-apk-signer** (APK Signing)
- **Version**: 1.2.1
- **Purpose**: V1+V2+V3 signature schemes
- **Why**: Handles modern Android signing complexity

**Features:**
- Aligns APK (optimization for device)
- Signs with multiple scheme versions
- Debug and release key support

#### 3. **YAHFA** (Yet Another Hook Framework for ART)
- **Version**: 0.10.0
- **Language**: C (native) + Java (interface)
- **Architecture**: JNI bridge to ART internals

**How It Works:**
```c
// Simplified concept from YAHFA
bool backupAndHookNative(ArtMethod* target, ArtMethod* hook, ArtMethod* backup) {
    // Save original entry point to backup
    backup->entry_point = target->entry_point;
    
    // Replace target entry point with hook
    target->entry_point = hook->entry_point;
    
    return true;
}
```

**ART Method Structure:**
```c
// Android Runtime internal structure (simplified)
class ArtMethod {
    void* entry_point_;           // Code to execute
    void* jni_trampoline_;        // For JNI methods
    uint32_t access_flags_;       // public/private/static
    uint32_t dex_method_index_;   // DEX file reference
    // ... more fields
};
```

#### 4. **Androguard** (APK Analysis)
- **Version**: 4.1.3
- **Language**: Python
- **Purpose**: Manifest parsing, resource reading

**Use Cases:**
```python
from androguard.core.apk import APK

apk = APK("app.apk")
manifest = apk.get_android_manifest_xml()  # Parsed XML
package = apk.get_package()                 # Package name
activities = apk.get_activities()           # All activities
```

### Development Tools

#### Gradle
- **Purpose**: Build hook APK (Java → DEX)
- **Version**: Configured in smali_generator/
- **Plugins**: Android Gradle Plugin, YAHFA dependency

#### Python 3
- **Libraries**:
  - `lxml`: XML parsing (AndroidManifest)
  - `cryptography`: Potential certificate handling
  - `requests`: Could be for downloading APKs
  - `pathlib`: Modern file path handling

### Reverse Engineering Techniques

#### Pattern-Based Code Discovery
```python
# Instead of brittle name-based search:
if "SubscriptionManager" in class_name:  # ❌ Breaks with obfuscation

# Use behavior patterns:
if '"subscribed_skus"' in class_data and re.search(r'\.method.*\(\)Z', class_data):  # ✅
```

#### Smali Analysis
```smali
# Recognizing boolean return
.method public final a()Z          # ()Z = returns boolean
    .locals 1
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z
    move-result v0
    return v0                      # Returns boolean result
.end method
```

**Key Smali Patterns:**
- `.method ... ()Z` → boolean return
- `.method ... (I)V` → void method with int parameter
- `invoke-static` → static method call
- `invoke-virtual` → instance method call
- `return-object` → return reference
- `const/4 v0, 0x1` → load int 1 into register v0

---

## Security Considerations

### Detection Mechanisms

Apps can detect modification through:

#### 1. Signature Verification
```java
// Check if app is signed with expected certificate
PackageInfo info = context.getPackageManager().getPackageInfo(
    context.getPackageName(), 
    PackageManager.GET_SIGNATURES
);
Signature sig = info.signatures[0];
if (!expectedSignature.equals(sig)) {
    // Modified APK detected!
}
```

**Bypass Difficulty**: High (requires hooking signature check itself)

#### 2. Installer Package Check
```java
// Check if installed from Google Play
String installer = context.getPackageManager().getInstallerPackageName(context.getPackageName());
if (!"com.android.vending".equals(installer)) {
    // Sideloaded APK!
}
```

**Bypass**: Can be hooked or package name spoofed

#### 3. Root Detection
```java
// Check for root indicators
boolean isRooted = new File("/system/app/Superuser.apk").exists()
    || new File("/system/xbin/su").exists()
    || canExecuteSu();
```

**Note**: This project doesn't require root, so this check isn't relevant

#### 4. Integrity Checks
```java
// CRC of DEX files
long actualCrc = calculateDexCrc();
if (actualCrc != EXPECTED_CRC) {
    // DEX modified!
}
```

**Bypass**: Hook CRC calculation or modify expected value

#### 5. Native Code Integrity
```c
// C code harder to hook
bool verify_integrity() {
    // Check if methods have expected entry points
    // Compare memory hashes
    return integrity_ok;
}
```

**Bypass Difficulty**: Very high (requires native hooking)

### Ethical & Legal Considerations

#### Educational Purpose
This project demonstrates:
- ✅ Security research methodology
- ✅ Android internals understanding
- ✅ Reverse engineering techniques
- ✅ Common vulnerability patterns

#### Prohibited Uses
- ❌ Distributing modified APKs
- ❌ Bypassing legitimate payment systems
- ❌ Violating Terms of Service
- ❌ Copyright infringement

#### Responsible Disclosure
**Proper Process:**
1. Discover vulnerability
2. Document findings
3. Report to vendor privately
4. Allow 90-day remediation period
5. Public disclosure (if agreed upon)

**This Project:**
- Demonstrates known client-side validation weakness
- Industry-standard knowledge: "never trust the client"
- Educational focus on technique, not exploitation

### Recommended Mitigations

#### For App Developers

**1. Server-Side Validation**
```java
// ❌ WRONG: Client decides
public boolean isPremium() {
    return sharedPrefs.getBoolean("premium", false);
}

// ✅ CORRECT: Server decides
public boolean isPremium() {
    String token = getAuthToken();
    Response response = api.checkSubscription(token);
    return response.isPremium;  // Server's word is final
}
```

**2. Certificate Pinning**
```java
// Prevent MITM attacks on API calls
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.moovit.com", "sha256/AAAAAAAAAA...")
        .build())
    .build();
```

**3. Integrity Checks**
```java
// Google Play Integrity API
IntegrityManager integrityManager = IntegrityManagerFactory.create(context);
integrityManager.requestIntegrityToken(
    IntegrityTokenRequest.builder()
        .setCloudProjectNumber(12345)
        .build()
).addOnSuccessListener(response -> {
    String token = response.token();
    // Send to server for verification
});
```

**4. Code Obfuscation (Defense in Depth)**
```groovy
// build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles 'proguard-rules.pro'
        }
    }
}
```

**5. Native Security Checks**
```c
// Harder to hook than Java
JNIEXPORT jboolean JNICALL
Java_com_app_Security_verifyIntegrity(JNIEnv *env, jobject obj) {
    // Check signature, installer, DEX integrity
    // Return result to Java
}
```

**6. Root/Tamper Detection**
```java
// SafetyNet Attestation API (legacy) / Play Integrity API (modern)
if (deviceIsCompromised()) {
    // Refuse to run or limit functionality
}
```

**Defense in Depth Principle:**
No single check is perfect; combine multiple layers:
- Signature verification (install time)
- Server-side validation (runtime)
- Integrity checks (periodic)
- Certificate pinning (network)
- Obfuscation (reverse engineering)

---

## Conclusion

### Key Takeaways

1. **Client-Side Validation Is Insufficient**
   - Any code running on user's device can be modified
   - Security decisions must happen server-side
   - Client code should be considered untrusted

2. **Obfuscation ≠ Security**
   - Renaming classes/methods only slows analysis
   - Behavioral patterns reveal functionality
   - Pattern matching defeats name-based obfuscation

3. **Android Security Model Has Limits**
   - Signature verification happens only at install
   - No runtime code integrity checks (by default)
   - Modified APKs work perfectly if re-signed

4. **Method Hooking Is Powerful**
   - YAHFA enables Java method replacement at runtime
   - Works on non-rooted devices (if embedded in APK)
   - Can bypass most Java-level protections

5. **Defense Requires Layers**
   - Server-side validation (critical)
   - Integrity checks (detection)
   - Certificate pinning (network security)
   - Native code (harder to hook)
   - Play Integrity API (device attestation)

### Project Scope

This research demonstrates:
- ✅ Smali analysis and modification
- ✅ Pattern-based code discovery
- ✅ Runtime method hooking with YAHFA
- ✅ APK repackaging workflow
- ✅ Client-side vulnerability exploitation

### Further Research Directions

1. **Server-Side Analysis**
   - Investigate API authentication
   - Test server-side validation presence
   - Attempt replay attacks with valid tokens

2. **Advanced Detection Evasion**
   - Hook signature verification methods
   - Bypass Play Integrity checks
   - Implement anti-debugging countermeasures

3. **Automated Patch Generation**
   - Machine learning for pattern discovery
   - Automated vulnerability scanning
   - Version-agnostic patch generation

4. **Native-Level Protections**
   - LLVM obfuscation analysis
   - Native integrity check bypass
   - Anti-hooking techniques

---

## References & Resources

### Academic Papers & Books
- Drake, J.J., Lanier, Z., Mulliner, C., Fora, P.O., Ridley, S.A., & Wicherski, G. (2014). *Android Hacker's Handbook*. Wiley. ISBN: 978-1118608647
- Elenkov, N. (2014). *Android Security Internals: An In-Depth Guide to Android's Security Architecture*. No Starch Press. ISBN: 978-1593275815
- OWASP Mobile Security Testing Guide (MSTG). Available at: https://owasp.org/www-project-mobile-security-testing-guide/

### Tools & Frameworks
- [apktool](https://ibotpeaches.github.io/Apktool/) - APK decompilation
- [YAHFA](https://github.com/PAGalaxyLab/YAHFA) - ART hooking framework
- [Androguard](https://github.com/androguard/androguard) - Android analysis
- [Frida](https://frida.re/) - Dynamic instrumentation

### Android Internals
- [Android Runtime (ART)](https://source.android.com/docs/core/runtime)
- [DEX File Format](https://source.android.com/docs/core/runtime/dex-format)
- [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)

### Security Best Practices
- [OWASP Mobile Application Security](https://owasp.org/www-project-mobile-app-security/)
- [Android Security Guidelines](https://developer.android.com/privacy-and-security/security-guidelines)
- [Google Play Integrity API](https://developer.android.com/google/play/integrity)

---

## License & Disclaimer

**Educational Purpose Only**

This project is intended solely for security research, education, and understanding Android security mechanisms. The techniques demonstrated here should only be used:
- In controlled research environments
- On applications you own or have permission to test
- For improving security awareness and defenses

**Prohibited Activities:**
- Distributing modified applications
- Circumventing payment systems
- Violating software Terms of Service
- Any unauthorized computer access

**Legal Notice:**
The authors assume no liability for misuse of this information. Users are responsible for ensuring their actions comply with applicable laws and regulations in their jurisdiction.

**Responsible Disclosure:**
If you discover vulnerabilities using these techniques, please follow responsible disclosure practices and report findings to the affected vendor before public disclosure.

---

*This documentation was created to explain the Android security research performed in the MoovitPatcher project. It should be used exclusively for educational purposes and improving mobile application security.*
