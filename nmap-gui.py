#!/usr/bin/env python3
'''
=======================================================
    NMAP GUI Wrapper built for HackEd

        Author: Bekhzod Umarov, 
                bumar1@unh.newhaven.edu
        Date:   02/10/2017
=======================================================
'''

print(__doc__)
import urwid, subprocess, sys, time

# ---------------------------------------------------------
# NMAP Walker
#  calls nmap and fills the urwid.ListBox with collected
#  data from nmap
class nmapWrapper(urwid.ListWalker):
    def __init__(self, settings, loop):
        self.mainloop = loop
        self.settings = settings
        self.focus = (0,1)
        self.data = ['','']
        write_fd = self.mainloop.watch_pipe(self.receive_output)

        cmds = ['nmap', settings['ip']]
        if len(self.settings['ports']) > 0:
            cmds.append( '-p'+self.settings['ports'] )
        #'opts'  : {'techniqs':'-sS','speed':'-T4','option':[]}
        if len(self.settings['opts']['techniqs']) > 0:
            cmds.append(self.settings['opts']['techniqs'])
        if len(self.settings['opts']['speed']) > 0:
            cmds.append(self.settings['opts']['speed'])
        if len(self.settings['opts']['option']) > 0:
            for each in self.settings['opts']['option']:
                cmds.append(each)

        self.proc = subprocess.Popen(
            cmds, stdout=write_fd,#self.writer, 
            stderr=write_fd, close_fds=True
        )
        self.data.append('')

    def receive_output(self, data):
        if data.decode('ascii') not in self.data:
            self.data.append(data.decode('ascii'))
        self.data.append('')
        self._modified()

    def _get_at_pos(self, pos):
        return urwid.Text( "{}".format(self.data[pos[1]]) ), pos

    def get_focus(self):
        return self._get_at_pos(self.focus)

    def set_focus(self, focus):
        self.focus = focus
        self._modified()

    def get_next(self, start_from):
        a,b = start_from
        #focus = b, a+b
        focus = a, b+1
        if b >= len(self.data) - 1:
            focus = a, len(self.data) - 1
        return self._get_at_pos(focus)

    def get_prev(self, start_from):
        a, b = start_from
        #focus = b-a, a
        focus = a,b-1
        if b < 0:
            focus = a, 0
        return self._get_at_pos(focus)

# ---------------------------------------------------------
# URWID GUI CLASS
class urGui():
    settings = { 'ip' : '', 'ports' : '', 
                 'opts'  : {'techniqs':'-sT','speed':'-T4','option':[]}
               }
    palette = [
        (None, 'light cyan', ''),
        ('body', '', '', 'standout'),
        ('foot', 'black', 'dark cyan'),
        ('key', 'dark red', 'black', 'underline'),
        ('title', 'black', 'dark cyan', 'standout'),
        ('reversed', 'dark cyan', 'dark red',''),
    ]
    #mainFrame = None#urwid.Frame()
    MENU = 0
    NMAP = 1
    curFrame = 0

    def __init__(self, ip=''):
        self.settings['ip'] = ip
        self.mainFrame = urwid.Frame(body=self.menuView())
        self.loop = urwid.MainLoop(
            self.mainFrame, 
            palette=self.palette, 
            unhandled_input=self.inputController
        )
    def menuView(self):
        self.curFrame = self.MENU
        choices = ['Enter IP','Enter Port(s)']
        techniq_labels = ['TCP', 'SYN (root)', 'ACK (root)', 'Window (root)', 'UDP (root)', 'IP Protocol (root)']
        techniq_opts  = ['-sT', '-sS', '-sA', '-sW',    '-sU', '-sO']

        speed_labels = ['Slow', 'Medium', 'Fast']
        speed_opts   = ['-T2', '-T4', '-T5']

        option_labels = ['Service/Version detection', 'Script Scan', 'OS Detection (root)']
        option_opts   = ['-sV', '-sC', '-O']

        selected = -1
        def run_menu(choices):
            body = [urwid.Text('nmapWrapper < by Bek @ HackEd >'), urwid.Divider()]

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            start = urwid.Button('Start')
            urwid.connect_signal(start, 'click', item_chosen, 'Start')
            body.append(urwid.AttrMap(start, None, focus_map='reversed'))

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            for c in choices:
                button = urwid.Button(c)
                urwid.connect_signal(button, 'click', item_chosen, c)
                body.append(urwid.AttrMap(button, None, focus_map='reversed'))

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            for o in option_labels:
                check = urwid.CheckBox(o, False)
                urwid.connect_signal(check, 'change', options_change, o)
                o_id = option_labels.index(o)
                if option_opts[o_id] in self.settings['opts']['option']:
                    check.set_state(True)
                body.append(urwid.AttrMap(check, None, focus_map='reversed'))
            

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            techniqs = []
            for t in techniq_labels:
                radio = urwid.RadioButton(techniqs, t)
                t_id = techniq_opts.index(self.settings['opts']['techniqs'])
                if t == techniq_labels[t_id]:
                    radio.set_state(True)
                urwid.connect_signal(radio, 'change', techniqs_change, t)
                body.append(urwid.AttrMap(radio, None, None) )

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            speeds = []
            for s in speed_labels:
                radio = urwid.RadioButton(speeds, s)
                urwid.connect_signal(radio, 'change', speed_change, s)
                s_id = speed_opts.index(self.settings['opts']['speed'])
                if s == speed_labels[s_id]:
                    radio.set_state(True)
                body.append(urwid.AttrMap(radio, None, None))

            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            body.append(urwid.AttrMap(urwid.Text(''), None, None))
            body.append(urwid.AttrMap(urwid.Text('Type "Q" to quit'), None, None))


            return urwid.ListBox(urwid.SimpleFocusListWalker(body))

        def options_change(check, new_state, o_label):
            o_id = option_labels.index(o_label)
            if new_state:
                if option_opts[o_id] not in self.settings['opts']['option']:
                    self.settings['opts']['option'].append(option_opts[o_id])
            else:
                if option_opts[o_id] in self.settings['opts']['option']:
                    _id = self.settings['opts']['option'].index(option_opts[o_id])
                    self.settings['opts']['option'].pop(_id)

        def techniqs_change(radio, new_state, t_label):
            if new_state:
                t = techniq_labels.index(t_label)
                self.settings['opts']['techniqs'] = techniq_opts[t]
        def speed_change(radio, new_state, s_label):
            if new_state:
                s = speed_labels.index(s_label)
                self.settings['opts']['speed'] = speed_opts[s]
            
        def item_chosen(button, choice):
            if choice in [ choices[0], choices[1] ]:
                if choice == choices[0]:
                    example = urwid.Text("Examples:\n > 192.168.0.1\n > 192.168.0.1-150\n > 192.168.0.0/24\n\n")
                    ask = urwid.Edit("Enter ip: ", edit_text=self.settings['ip'])
                elif choice == choices[1]:
                    example = urwid.Text("Examples:\n > 22\n > -\n > 0-1000\n\n")
                    ask = urwid.Edit("Enter port(s): ", edit_text=self.settings['ports'])
                urwid.connect_signal(ask, 'change', on_ask_change, choices.index(choice))
                done = urwid.Button('Ok')
                urwid.connect_signal(done, 'click', exit_program)
                menuloop.original_widget = urwid.Filler(urwid.Pile([example,ask,
                    urwid.AttrMap(done, None, focus_map='reversed')]))
            else:
                self.mainFrame.body = self.nmapView()

        def on_ask_change(edit, new_edit_text, selected):
            if selected == 0:
                self.settings['ip'] = new_edit_text
            elif selected == 1:
                self.settings['ports'] = new_edit_text

        def exit_program(button):
            self.mainFrame.body = self.menuView()

        menuloop= urwid.Padding(run_menu(choices), left=2, right=2)
        top = urwid.Overlay(menuloop, urwid.SolidFill(u'\N{MEDIUM SHADE}'),
                align='center', width=('relative', 60),
                valign='middle', height=('relative', 60),
                min_width=20, min_height=9)
        return top

    def nmapView(self):
        self.curFrame = self.NMAP
        footer_text = [
            ('title', "NMAP Wrapper"), "    ",
            ('key', " UP "), ", ",
            ('key', " DOWN "), ", ",
            ('key', " PAGE UP "), " and ",
            ('key', " PAGE DOWN "), " - move view  |   ",
            ('key', " B "), " - go back  |  ",
            ('key', " Q "), " - exit",
        ]

        listbox = urwid.ListBox(nmapWrapper(self.settings, self.loop))
        footer  = urwid.AttrMap(urwid.Text(footer_text), 'foot')
        view    = urwid.Frame(urwid.AttrWrap(listbox, 'body'), footer=footer)
        return view

    def inputController(self, key):
        if key in ['q','Q']:
            raise urwid.ExitMainLoop()
        if self.curFrame == self.MENU:
            pass
        elif self.curFrame == self.NMAP:
            if key in ['b','B']:
                self.mainFrame.body = self.menuView()

    def run(self):
        self.mainFrame.body = self.menuView()
        self.loop.run()







# ---------------------------------------------------------
# Run
if __name__=='__main__':
    ip = ''
    if len(sys.argv) > 1:
        try:
            import re
            regex = r"[\d+\.]{7,15}"
            if sys.argv[0] in 'python':
                m = re.search(regex, sys.argv[2])
            else:
                m = re.search(regex, sys.argv[1])
            ip = m.group(0)
        except Exception as e:
            print(e)

    g = urGui(ip=ip)
    g.run()


def factor():
    factor_me = 9278317281738917298371937112213123131

    output_widget = urwid.Text("Factors of %d:\n" % factor_me)
    edit_widget = urwid.Edit("Type anything or press enter to exit:")
    frame_widget = urwid.Frame(
        header=edit_widget,
        body=urwid.Filler(output_widget, valign='bottom'),
        focus_part='header')

    def exit_on_enter(key):
        if key == 'enter': raise urwid.ExitMainLoop()

    loop = urwid.MainLoop(frame_widget, unhandled_input=exit_on_enter)

    def received_output(data):
        output_widget.set_text( output_widget.text + data.decode('ascii') )

    write_fd = loop.watch_pipe(received_output)
    proc = subprocess.Popen(
        ['ping', '172.29.27.184'],
        stdout=write_fd,
        close_fds=True)

    proc.kill()

