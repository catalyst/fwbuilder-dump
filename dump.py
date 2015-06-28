#!/usr/bin/env python
#
# Copyright (c) 2015 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Mucking about with some code to convert fwbuilder files in to HTML.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import sys
from lxml import etree

NAMESPACES = {'f': 'http://www.fwbuilder.org/1.0/'}
FIREWALL = sys.argv[2]

def indent(text, depth):
    return "%s%s" % (' ' * depth, text)

def deref_object(ref_object):
    targets = []

    try:
        for target in ref_object.xpath("*[@ref]"):
            targets.append(object_by_id(target.get('ref'), ref_object))
    except AttributeError:
        pass

    return targets

def object_by_id(object_id, tree):
    return tree.xpath("//*[@id='%s']" % object_id)[0]

def branch_dest(rule):
    return rule.xpath("f:PolicyRuleOptions/f:Option[@name='branch_id']", namespaces=NAMESPACES)[0].text

def forward_only(rule):
    try:
        return rule.xpath("f:PolicyRuleOptions/f:Option[@name='firewall_is_part_of_any_and_networks']", namespaces=NAMESPACES)[0].text == '0'
    except:
        return False

def get_addresses(srcdst):
    if srcdst.tag.endswith('Firewall'):
        if srcdst.get('name') == FIREWALL:
            return ['The server on which this firewall is deployed']
        else:
            return ['The firewall %s' % srcdst.get('name')]
    elif srcdst.tag.endswith('AddressTable'):
        if srcdst.get('run_time') == 'True':
            return ['Address table <tt>%s</tt> loaded from the firewall' % srcdst.get('filename')]
        else:
            return ['Address table <tt>%s</tt> loaded during compile time' % srcdst.get('filename')]

    addresses = []

    for adrobj in deref_object(srcdst):
        if adrobj.tag.startswith('{http://www.fwbuilder.org/1.0/}Any'):
            return ['Any address']

        address = adrobj.get('address')
        comment = adrobj.get('comment').strip()
        name = adrobj.get('name').strip()
        netmask = adrobj.get('netmask')

        if netmask and adrobj.tag.endswith('Network'):
            address = "%s/%s" % (address, netmask)

        if comment:
            comment = " <em>(%s)</em>" % comment

        if address:
            addresses.append("%s <tt>%s</tt>%s" % (name, address, comment))
        else:
            addresses += get_addresses(adrobj)

    return addresses

def dump_policy(policy, depth=0):
    reference_objects = {}
    output_string = "<ol>"

    for rule in policy.xpath("f:PolicyRule", namespaces=NAMESPACES):
        src_object = rule.xpath("f:Src", namespaces=NAMESPACES)[0]
        src = ', '.join([src.get('name') for src in deref_object(src_object)])
        if src == 'Any':
            src = 'any source'
        src_id = deref_object(src_object)[0].get('id')

        dst_object = rule.xpath("f:Dst", namespaces=NAMESPACES)[0]
        dst = ', '.join([dst.get('name') for dst in deref_object(dst_object)])
        if dst == 'Any':
            dst = 'any destination'

        dst_id = deref_object(dst_object)[0].get('id')

        if deref_object(src_object)[0].tag.endswith('Firewall') and deref_object(src_object)[0].get('name') == FIREWALL:
            src = 'this firewall server'

        if deref_object(dst_object)[0].tag.endswith('Firewall') and deref_object(dst_object)[0].get('name') == FIREWALL:
            dst = 'this firewall server'

        interface = deref_object(rule.xpath("f:Itf", namespaces=NAMESPACES)[0])[0].get('name')
        interface_label = deref_object(rule.xpath("f:Itf", namespaces=NAMESPACES)[0])[0].get('label')
        if interface_label:
            interface = "<tt>%s</tt> <em>(%s)</em>" % (interface, interface_label)
        else:
            interface = "<tt>%s</tt>" % interface
        service_objects = deref_object(rule.xpath("f:Srv", namespaces=NAMESPACES)[0])
        services = [service.get('name') for service in service_objects]

        if services == ['Any']:
            services = []

        direction = rule.get('direction')

        if src_object.get('neg') == 'True':
            src = "not %s" % src

        if dst_object.get('neg') == 'True':
            dst = "not %s" % dst

        if direction == 'Both':
            direction = ''

        if src != 'any source' or dst != 'any destination':

            if src_id not in reference_objects:
                reference_objects[src_id] = {'name': src, 'addresses': get_addresses(src_object), 'ref_type':'address'}
            if dst_id not in reference_objects:
                reference_objects[dst_id] = {'name': dst, 'addresses': get_addresses(dst_object), 'ref_type':'address'}

            if 'Address' not in deref_object(dst_object)[0].tag:
                src = 'packets from <a href="#%s">%s</a>' % (src_id, src)
            else:
                src = '<a href="#%s">%s</a>' % (src_id, src)

            src_dst = '%s to <a href="#%s">%s</a>' % (src, dst_id, dst)
        elif forward_only(rule):
            src_dst = "any packets <em>forwarded through</em> this firewall"
        else:
            src_dst = '<a href="#%s">any packets</a>' % src_id


        action = rule.get('action')
        if action == 'Branch':
            dest_name = object_by_id(branch_dest(rule), rule).get('name')
            action = 'Branch to policy <strong>%s</strong></span><span><a name="branch-%s"></a> for ' % (dest_name, dest_name)
        elif action == 'Continue' and rule.get('log') == 'True':
            action = 'Log'

        if services:
            if len(services) == 1:
                services = 'for service <tt>%s</tt>' % '</tt>, <tt>'.join(services)
            else:
                services = 'for services <tt>%s</tt>' % '</tt>, <tt>'.join(services)

        else:
            services = ''

        if interface == '<tt>Any</tt>' and action.startswith('Branch'):
            interface = 'via any interface'
        elif interface == '<tt>Any</tt>' and direction != 'Both':
            interface = ''
        else:
            interface = 'via interface %s' % interface

        comment = rule.get('comment').strip()

        if comment:
            comment = "<em>(%s)</em>" % comment
        css_class = action.lower().split()[0]

        if action == 'Accept':
            action = 'Allow'

        output_string += indent('<li class="rule-%s"><span class="rule-%s">%s</span> %s %s %s %s %s</li>' % (css_class, css_class, action, src_dst, direction.lower(), interface, services, comment), depth + 1)

        if rule.get('action') == 'Branch':
            output_string += indent("<ol>", depth + 1)
            subpolicy, discovered_references = dump_policy(policy.getparent().xpath("f:Policy[@id='%s']" % branch_dest(rule), namespaces=NAMESPACES)[0], depth+1)
            output_string += subpolicy
            reference_objects = dict(reference_objects.items() + discovered_references.items())
            output_string += indent("</ol>", depth + 1)

    if depth == 0:
        output_string += '<li><span class="rule-discard">Deny</span> any packets that remain</li>'
    output_string += "</ol>"

    if 'sysid0' in reference_objects:
        reference_objects['sysid0']['name'] = 'Anything'

    return (output_string, reference_objects)

if __name__ == "__main__":
    with open(sys.argv[1]) as fp:
        fw = etree.parse(fp)

    this_firewall = fw.xpath("/f:FWObjectDatabase/f:Library[@name='User']/f:ObjectGroup[@name='Firewalls']/f:Firewall[@name='%s']" % FIREWALL, namespaces=NAMESPACES)[0]

    print """
<!doctype html>
<html>
    <head>
        <style>
            body {
                font-family: sans-serif;
            }
            dt:target {
                font-weight: bold;
            }
            dt:target + dd {
                color: #555753;
            }
            dd {
                padding-bottom: 15px;
            }

            a:link, a:visited {
                color: #555753;
                text-decoration: none;
            }

            a:hover {
                text-decoration: underline;
            }

            span.rule-accept {
                color: #73d216;
            }

            span.rule-discard {
                color: #cc0000;
            }

            span.rule-branch {
                color: #3465a4;
            }

            li.rule-branch {
                background-color: #eeeeec;
            }

            span.rule-log {
                color: #75507b;
            }

            li {
                list-style: #d3d7cf;
                padding: 3px;
                margin: 3px;
            }

            ol {
                list-style-type: none;
                counter-reset: ol-counter;
            }

            ol > li:before {
                content: counter(ol-counter) ' ';
                counter-increment: ol-counter;
                color: #888a85;
            }
        </style>
    <body>
    <h1>Catalyst firewall report for '%s'</h1>
    <h2>Policy</h2>
    """ % FIREWALL

    policy_string, references = dump_policy(this_firewall.xpath("f:Policy[@name='Policy']", namespaces=NAMESPACES)[0])
    print policy_string
    print "<h2>Definitions</h2><dl>"
    for reference_id, reference in references.iteritems():
        print """<dt id="%s">%s</dt><dd>%s
        </dd>""" % (reference_id, reference['name'], '<br>'.join(reference['addresses']))
    print "</body></html>"
