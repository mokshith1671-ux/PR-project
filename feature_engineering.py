import os
import json
import math
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    'n_events', 'unique_event_types', 'weighted_event_score', 'behavioral_entropy',
    'temporal_span_ms', 'temporal_entropy', 'unique_file_paths', 'unique_urls',
    'unique_networks', 'unique_crypto_algos', 'unique_shared_prefs', 'has_runtime_exec',
    'has_dex_load', 'has_sms', 'has_socket', 'has_crypto', 'has_subscriber_id',
    'has_device_id', 'has_webview', 'has_url', 'has_network', 'has_process',
    'has_settings', 'cnt_runtime_exec', 'cnt_dex_load', 'cnt_sms', 'cnt_socket',
    'cnt_subscriber_id_access', 'cnt_device_id_access', 'cnt_crypto', 'cnt_webview',
    'cnt_url_access', 'cnt_okhttp', 'cnt_network', 'cnt_process', 'cnt_start_activity',
    'cnt_activity_resume', 'cnt_activity', 'cnt_settings_access', 'cnt_settings',
    'cnt_device', 'cnt_file', 'cnt_file_access', 'cnt_shared_pref', 'cnt_sp',
    'cnt_runtime', 'cnt_unknown', 'file_access_ratio', 'network_ratio', 'sp_ratio',
    'high_signal_ratio', 'crypto_and_network', 'device_id_and_network', 'dex_and_exec',
    'webview_and_url', 'sms_and_device', 'richness_score', 'quality_score',
    'log_n_events', 'log_weighted_score', 'log_file_paths', 'log_urls'
]

def calculate_entropy(categories):
    if not categories:
        return 0.0
    total = len(categories)
    counts = {}
    for item in categories:
        counts[item] = counts.get(item, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return float(entropy)

def extract_features_from_json(json_input):
    if isinstance(json_input, str):
        if os.path.exists(json_input):
            with open(json_input, 'r', encoding='utf-8') as f:
                events = json.load(f)
        else:
            events = json.loads(json_input)
    elif isinstance(json_input, list):
        events = json_input
    else:
        events = []

    if not isinstance(events, list):
        events = []

    n_events = float(len(events))
    
    event_types = []
    timestamps = []
    file_paths = set()
    urls = set()
    networks = set()
    crypto_algos = set()
    sp_keys = set()

    type_counts = {}

    for event in events:
        if not isinstance(event, dict):
            continue
        
        etype = str(event.get('type', 'unknown')).lower()
        event_types.append(etype)
        type_counts[etype] = type_counts.get(etype, 0) + 1

        if 'ts' in event and isinstance(event['ts'], (int, float)):
            timestamps.append(event['ts'])

        data = event.get('data', {})
        if isinstance(data, dict):
            if etype in ['file', 'file_access']:
                path = data.get('path') or data.get('file')
                if path:
                    file_paths.add(str(path))
            elif etype in ['network', 'url', 'url_access', 'okhttp']:
                url = data.get('url') or data.get('host')
                if url:
                    urls.add(str(url))
                    networks.add(str(url).split('/')[0])
            elif etype == 'crypto':
                algo = data.get('algorithm') or data.get('cipher')
                if algo:
                    crypto_algos.add(str(algo))
            elif etype in ['sp', 'shared_pref']:
                key = data.get('key')
                if key:
                    sp_keys.add(str(key))

    unique_event_types = float(len(set(event_types)))
    behavioral_entropy = calculate_entropy(event_types)

    if len(timestamps) > 1:
        timestamps.sort()
        temporal_span_ms = float(timestamps[-1] - timestamps[0])
        deltas = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        temporal_entropy = calculate_entropy([min(100, int(d / 100)) for d in deltas])
    else:
        temporal_span_ms = 0.0
        temporal_entropy = 0.0

    unique_file_paths = float(len(file_paths))
    unique_urls = float(len(urls))
    unique_networks = float(len(networks))
    unique_crypto_algos = float(len(crypto_algos))
    unique_shared_prefs = float(len(sp_keys))

    cnt_runtime_exec = float(type_counts.get('runtime_exec', 0) + type_counts.get('runtime', 0))
    cnt_dex_load = float(type_counts.get('dex_load', 0))
    cnt_sms = float(type_counts.get('sms', 0))
    cnt_socket = float(type_counts.get('socket', 0))
    cnt_subscriber_id_access = float(type_counts.get('subscriber_id', 0) + type_counts.get('subscriber_id_access', 0))
    cnt_device_id_access = float(type_counts.get('device', 0) + type_counts.get('device_id', 0) + type_counts.get('device_id_access', 0))
    cnt_crypto = float(type_counts.get('crypto', 0))
    cnt_webview = float(type_counts.get('webview', 0))
    cnt_url_access = float(type_counts.get('url', 0) + type_counts.get('url_access', 0))
    cnt_okhttp = float(type_counts.get('okhttp', 0))
    cnt_network = float(type_counts.get('network', 0))
    cnt_process = float(type_counts.get('process', 0))
    cnt_start_activity = float(type_counts.get('start_activity', 0))
    cnt_activity_resume = float(type_counts.get('activity_resume', 0))
    cnt_activity = float(type_counts.get('activity', 0))
    cnt_settings_access = float(type_counts.get('settings_access', 0))
    cnt_settings = float(type_counts.get('settings', 0))
    cnt_device = cnt_device_id_access
    cnt_file = float(type_counts.get('file', 0))
    cnt_file_access = float(type_counts.get('file_access', 0))
    cnt_shared_pref = float(type_counts.get('shared_pref', 0))
    cnt_sp = float(type_counts.get('sp', 0))
    cnt_runtime = cnt_runtime_exec
    cnt_unknown = float(type_counts.get('unknown', 0))

    has_runtime_exec = 1.0 if cnt_runtime_exec > 0 else 0.0
    has_dex_load = 1.0 if cnt_dex_load > 0 else 0.0
    has_sms = 1.0 if cnt_sms > 0 else 0.0
    has_socket = 1.0 if cnt_socket > 0 else 0.0
    has_crypto = 1.0 if cnt_crypto > 0 else 0.0
    has_subscriber_id = 1.0 if cnt_subscriber_id_access > 0 else 0.0
    has_device_id = 1.0 if cnt_device_id_access > 0 else 0.0
    has_webview = 1.0 if cnt_webview > 0 else 0.0
    has_url = 1.0 if (cnt_url_access > 0 or unique_urls > 0) else 0.0
    has_network = 1.0 if (cnt_network > 0 or cnt_okhttp > 0 or cnt_url_access > 0) else 0.0
    has_process = 1.0 if cnt_process > 0 else 0.0
    has_settings = 1.0 if (cnt_settings > 0 or cnt_settings_access > 0) else 0.0

    denom = max(1.0, n_events)
    file_access_ratio = (cnt_file + cnt_file_access) / denom
    network_ratio = (cnt_network + cnt_url_access + cnt_okhttp) / denom
    sp_ratio = (cnt_sp + cnt_shared_pref) / denom

    high_signal_count = (cnt_runtime_exec + cnt_dex_load + cnt_sms + cnt_socket + cnt_crypto + cnt_device_id_access)
    high_signal_ratio = high_signal_count / denom

    crypto_and_network = 1.0 if (has_crypto and has_network) else 0.0
    device_id_and_network = 1.0 if (has_device_id and has_network) else 0.0
    dex_and_exec = 1.0 if (has_dex_load and has_runtime_exec) else 0.0
    webview_and_url = 1.0 if (has_webview and has_url) else 0.0
    sms_and_device = 1.0 if (has_sms and has_device_id) else 0.0

    weighted_event_score = (
        cnt_runtime_exec * 5.0 +
        cnt_dex_load * 4.5 +
        cnt_sms * 4.5 +
        cnt_socket * 4.0 +
        cnt_crypto * 3.5 +
        cnt_device_id_access * 3.5 +
        (cnt_network + cnt_url_access) * 2.5 +
        cnt_activity * 1.0 +
        (cnt_file + cnt_file_access) * 0.5 +
        (cnt_sp + cnt_shared_pref) * 0.5
    )

    richness_score = min(1.0, unique_event_types / 10.0)
    quality_score = min(1.0, (math.log1p(n_events) / 6.0) * 0.5 + richness_score * 0.5)

    log_n_events = math.log1p(n_events)
    log_weighted_score = math.log1p(weighted_event_score)
    log_file_paths = math.log1p(unique_file_paths)
    log_urls = math.log1p(unique_urls)

    feat_dict = {
        'n_events': n_events,
        'unique_event_types': unique_event_types,
        'weighted_event_score': weighted_event_score,
        'behavioral_entropy': behavioral_entropy,
        'temporal_span_ms': temporal_span_ms,
        'temporal_entropy': temporal_entropy,
        'unique_file_paths': unique_file_paths,
        'unique_urls': unique_urls,
        'unique_networks': unique_networks,
        'unique_crypto_algos': unique_crypto_algos,
        'unique_shared_prefs': unique_shared_prefs,
        'has_runtime_exec': has_runtime_exec,
        'has_dex_load': has_dex_load,
        'has_sms': has_sms,
        'has_socket': has_socket,
        'has_crypto': has_crypto,
        'has_subscriber_id': has_subscriber_id,
        'has_device_id': has_device_id,
        'has_webview': has_webview,
        'has_url': has_url,
        'has_network': has_network,
        'has_process': has_process,
        'has_settings': has_settings,
        'cnt_runtime_exec': cnt_runtime_exec,
        'cnt_dex_load': cnt_dex_load,
        'cnt_sms': cnt_sms,
        'cnt_socket': cnt_socket,
        'cnt_subscriber_id_access': cnt_subscriber_id_access,
        'cnt_device_id_access': cnt_device_id_access,
        'cnt_crypto': cnt_crypto,
        'cnt_webview': cnt_webview,
        'cnt_url_access': cnt_url_access,
        'cnt_okhttp': cnt_okhttp,
        'cnt_network': cnt_network,
        'cnt_process': cnt_process,
        'cnt_start_activity': cnt_start_activity,
        'cnt_activity_resume': cnt_activity_resume,
        'cnt_activity': cnt_activity,
        'cnt_settings_access': cnt_settings_access,
        'cnt_settings': cnt_settings,
        'cnt_device': cnt_device,
        'cnt_file': cnt_file,
        'cnt_file_access': cnt_file_access,
        'cnt_shared_pref': cnt_shared_pref,
        'cnt_sp': cnt_sp,
        'cnt_runtime': cnt_runtime,
        'cnt_unknown': cnt_unknown,
        'file_access_ratio': file_access_ratio,
        'network_ratio': network_ratio,
        'sp_ratio': sp_ratio,
        'high_signal_ratio': high_signal_ratio,
        'crypto_and_network': crypto_and_network,
        'device_id_and_network': device_id_and_network,
        'dex_and_exec': dex_and_exec,
        'webview_and_url': webview_and_url,
        'sms_and_device': sms_and_device,
        'richness_score': richness_score,
        'quality_score': quality_score,
        'log_n_events': log_n_events,
        'log_weighted_score': log_weighted_score,
        'log_file_paths': log_file_paths,
        'log_urls': log_urls
    }

    df = pd.DataFrame([feat_dict], columns=FEATURE_COLUMNS)
    return df
