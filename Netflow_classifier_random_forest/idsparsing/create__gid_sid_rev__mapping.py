import glob
from pprint import pprint

def parse_rule(line, verbose=False):
    rule = {}

    line = line.strip()

    if verbose:
        print('-'*80)
        print(line)
        print()

    splitted = line.split('(')
    action_header = splitted[0]
    options = '('.join(splitted[1:])
    # Remove last character, i.e. ')'
    options = options[:-1]

    action_header_ = action_header.split(' ')
    action = action_header_[0]
    header = ' '.join(action_header_[1:])

    rule['action'] = action

    if verbose:
        print('action:', action)
        print('header:', header)
        print('options:', options)

    # The characters ; and " have special meaning in the Suricata rule language and must be escaped when used in a rule option value.
    if verbose and ('\\;' in options or '\\"' in options):
        print("-> ';' or '\"' found in some options")
        print(line)

    for option in options.split(';'):
        option = option.strip()

        # If options terminates with a last ';', split() would have a last, empty, option.
        # e.g. "alert tcp $EXTERNAL_NET any -> $HOME_NET 7597 (msg: [...] rev:12;)"
        if option == '':
            continue

        if verbose:
            print('  option:', option)

        # Some options can include settings, specified by the keyword of the option, followed by a colon, followed by the settings.
        option_ = option.split(':')
        kwd = option_[0]
        if len(option_) > 1:
            settings = ':'.join( option_[1:])
        else:
            settings = ''
        if verbose:
            print('  kwd:', kwd)
            print('  settings:', settings)

        # Keep relevant options based on a whitelis
        if kwd in ['classtype', 'sid', 'rev', 'gid', 'target', 'priority']:
            rule[kwd] = settings

        if 'gid' not in rule:
            # Default
            rule['gid'] = '1'

        rule['raw'] = line

    if verbose:
        pprint(rule)

    return rule

def process_rules_file(fname, verbose=False):
    with open(fname, 'r') as f:
        lines = f.readlines()

    rules = []
    cnt = 0
    for line in lines:
        if line[0] in ['#', '\n']:
            # Skip commented or empty lines
            continue
        cnt += 1
        try:
            rule = parse_rule(line, verbose)
            if rule:
                rule['fname'] = fname
                rules.append(rule)
        except Exception as e:
            print('Exception "%s: %s" raised while parsing line "%s"' % (e.__class__.__name__, e, line))

    print('Parsed %d rules out of %d' % (len(rules), cnt))

    return rules

if __name__ == "__main__":
    fnames = []
    fnames += glob.glob('data/ET_rules/*.rules') # Suricata default
    fnames += glob.glob('data/suricata_rules/*.rules') # Suricata GH repo
    fnames += glob.glob('data/snort2_rules/*.rules') # Snort 2
    fnames += glob.glob('data/snort3_rules/*.rules') # Snort 3
    rules = []
    for fname in fnames:
        print('Processing', fname)
        rules += process_rules_file(fname)

    gid_sid_rev__to__classtype__mapping = {}
    gid_sid_rev__to__classtype__ambiguous_mapping = {}
    skipped = 0
    for rule in rules:
        if 'classtype' not in rule:
            skipped += 1
            pprint(rule)
            continue

        gid, sid, rev = rule['gid'], rule['sid'], rule['rev']
        gsr = '%s:%s:%s' % (gid, sid, rev)
        if gsr in gid_sid_rev__to__classtype__mapping:
            # gid-sid-rev already stored...
            if gid_sid_rev__to__classtype__mapping[gsr] != rule['classtype']:
                # ...with a different mapping!
                if gsr not in gid_sid_rev__to__classtype__ambiguous_mapping:
                    gid_sid_rev__to__classtype__ambiguous_mapping[gsr] = set()
                gid_sid_rev__to__classtype__ambiguous_mapping[gsr].add( rule['classtype'] )
                gid_sid_rev__to__classtype__ambiguous_mapping[gsr].add( gid_sid_rev__to__classtype__mapping[gsr] )

        gid_sid_rev__to__classtype__mapping[gsr] = rule['classtype']

    print('\nSkipped %d rules out of %d (no classtype found)\n' % (skipped, len(rules)))

    if len(gid_sid_rev__to__classtype__ambiguous_mapping) > 0:
        print('Ambiguous mappings:')
        for gsr in gid_sid_rev__to__classtype__ambiguous_mapping:
            print(gsr, '-->', gid_sid_rev__to__classtype__ambiguous_mapping[gsr])

    with open('gid_sid_rev__to__classtype__mapping.csv', 'w') as f:
        for gsr,cls in gid_sid_rev__to__classtype__mapping.items():
            f.write('%s,%s\n' % (gsr,cls))
