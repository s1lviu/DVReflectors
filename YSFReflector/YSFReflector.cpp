/*
*   Copyright (C) 2016,2018,2020,2021 by Jonathan Naylor G4KLX
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "YSFReflector.h" // Must match the target state above
#include "YSFDefines.h"
#include "BlockList.h"
#include "StopWatch.h"
#include "Network.h"
#include "Version.h"
#include "Thread.h"
#include "Log.h"
#include "GitVersion.h"
// Timer.h is included via YSFReflector.h

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "YSFReflector.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/YSFReflector.ini";
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cstring> // For ::memcpy, ::memset
#include <string>  // For std::string (used in LogMessage for PTT sequence)

// Constants PRIVATE_ROOM_DGID, PTT_SEQUENCE_COUNT_TARGET, PTT_SEQUENCE_WINDOW_SECONDS
// are defined in YSFReflector.h

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "YSFReflector version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: YSFReflector [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

	CYSFReflector* reflector = new CYSFReflector(std::string(iniFile));
	reflector->run();
	delete reflector;

	return 0;
}

CYSFReflector::CYSFReflector(const std::string& file) :
    m_conf(file),
    m_repeaters(),
    // Initialize existing members (already in your YSFReflector.h)
    m_txActive(false),
    // m_currentAddr and m_currentAddrLen are fine without explicit init here
    // NEW members for the feature:
    m_currentRptObject(nullptr),
    m_currentNumericDGID(0)
{
	CUDPSocket::startup();
    // Initialize existing buffers (already in your YSFReflector.h)
    ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH);
    ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
    ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH);
}

CYSFReflector::~CYSFReflector()
{
    // Clean up dynamically allocated CYSFRepeater objects
    for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
        delete *it;
    }
    m_repeaters.clear();
	CUDPSocket::shutdown();
}

void CYSFReflector::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "YSFReflector: cannot read the .ini file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon_local = m_conf.getDaemon(); // Renamed to m_daemon_local to avoid confusion if m_daemon was a member
	if (m_daemon_local) { // Use local variable
		pid_t pid = ::fork();
		if (pid == -1) { ::fprintf(stderr, "Couldn't fork() , exiting\n"); return; }
		else if (pid != 0) { exit(EXIT_SUCCESS); }
		if (::setsid() == -1) { ::fprintf(stderr, "Couldn't setsid(), exiting\n"); return; }
		if (::chdir("/") == -1) { ::fprintf(stderr, "Couldn't cd /, exiting\n"); return; }
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == NULL) { ::fprintf(stderr, "Could not get the mmdvm user, exiting\n"); return; }
			uid_t mmdvm_uid = user->pw_uid; gid_t mmdvm_gid = user->pw_gid;
			if (setgid(mmdvm_gid) != 0) { ::fprintf(stderr, "Could not set mmdvm GID, exiting\n"); return; }
			if (setuid(mmdvm_uid) != 0) { ::fprintf(stderr, "Could not set mmdvm UID, exiting\n"); return; }
			if (setuid(0) != -1) { ::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n"); return; }
		}
	}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
        ret = ::LogInitialise(m_daemon_local, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#else
        ret = ::LogInitialise(false, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#endif
	if (!ret) { ::fprintf(stderr, "YSFReflector: unable to open the log file\n"); return; }

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon_local) { // Use local variable
		::close(STDIN_FILENO); ::close(STDOUT_FILENO); ::close(STDERR_FILENO);
	}
#endif

	CNetwork network(m_conf.getNetworkPort(), m_conf.getId(), m_conf.getName(), m_conf.getDescription(), m_conf.getNetworkDebug());
	ret = network.open();
	if (!ret) { ::LogFinalise(); return; }

	CBlockList blockList(m_conf.getBlockListFile(), m_conf.getBlockListTime());
	blockList.start();

	network.setCount(0);

	CStopWatch stopWatch;
	stopWatch.start();

	CTimer dumpTimer(1000U, 120U); dumpTimer.start();
	CTimer pollTimer(1000U, 5U); pollTimer.start();

	LogMessage("YSFReflector-%s is starting", VERSION);
	LogMessage("Built %s %s (GitID #%.7s)", __TIME__, __DATE__, gitversion);

	CTimer watchdogTimer(1000U, 0U, 1500U); // Preserving original initialization (1.5s timeout)
    // watchdogTimer.stop(); // It will be started when TX becomes active

	for (;;) {
		unsigned char buffer[200U];
		sockaddr_storage addr;
		unsigned int addrLen = sizeof(sockaddr_storage); // Initialize for recvfrom

		unsigned int len = network.readData(buffer, 200U, addr, addrLen);
		if (len > 0U) {
			CYSFRepeater* rpt = findRepeater(addr);

			if (::memcmp(buffer, "YSFP", 4U) == 0) {
				if (rpt == NULL) {
					rpt = new CYSFRepeater; // Constructor initializes new members like m_pttSequenceTimer
					rpt->m_callsign = std::string((char*)(buffer + 4U), YSF_CALLSIGN_LENGTH); // YSF_CALLSIGN_LENGTH used here
					// Strip trailing spaces from callsign for cleaner logs if CYSFRepeater doesn't do it
                    rpt->m_callsign.erase(rpt->m_callsign.find_last_not_of(' ') + 1);
					::memcpy(&rpt->m_addr, &addr, addrLen); // Use actual addrLen from readData
					rpt->m_addrLen  = addrLen;
					m_repeaters.push_back(rpt);
					network.setCount(m_repeaters.size());
					char buff[80U]; // Original log buffer
					LogMessage("Adding %s (%s)", rpt->m_callsign.c_str(), CUDPSocket::display(addr, buff, 80U));
				}
				rpt->m_timer.start(); // Existing keep-alive timer start
				network.writePoll(addr, addrLen);
			} else if (::memcmp(buffer + 0U, "YSFU", 4U) == 0 && rpt != NULL) {
				char buff[80U]; // Original log buffer
				LogMessage("Removing %s (%s) unlinked", rpt->m_callsign.c_str(), CUDPSocket::display(rpt->m_addr, buff, 80U)); // rpt->m_addr used here

                if (m_txActive && m_currentRptObject == rpt) {
                    // Log for TXer unlinking is handled by existing EOT or watchdog logic if TX drops.
                    // Clear TX state if the current transmitter unlinks.
                    m_txActive = false;
                    watchdogTimer.stop();
                    ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH); ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
                    ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH);
                    m_currentRptObject = nullptr; m_currentNumericDGID = 0;
                }

				for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
					if (*it == rpt) { // Compare by pointer as rpt is from findRepeater or new
						delete *it;
						m_repeaters.erase(it);
						break;
					}
				}
				network.setCount(m_repeaters.size());
			} else if (::memcmp(buffer + 0U, "YSFD", 4U) == 0 && rpt != NULL) {
			    unsigned char incomingTag[YSF_CALLSIGN_LENGTH];
                unsigned char incomingSrc[YSF_CALLSIGN_LENGTH];
                unsigned char incomingDstText[YSF_CALLSIGN_LENGTH]; // Renamed for clarity from original 'incomingDst'

                ::memcpy(incomingTag, buffer + 4U, YSF_CALLSIGN_LENGTH);
                ::memcpy(incomingSrc, buffer + 14U, YSF_CALLSIGN_LENGTH);
                ::memcpy(incomingDstText, buffer + 24U, YSF_CALLSIGN_LENGTH); // Used to be incomingDst

                // Blocklist check (using original logic)
                bool isBlocked = false;
                if (!m_txActive) {
                    isBlocked = blockList.check(incomingSrc);
                } else {
                    isBlocked = blockList.check(incomingSrc) || blockList.check(m_currentSrc);
                }

                if (isBlocked) {
                    if (m_txActive && m_currentRptObject == rpt) { // Check if current TXer is the one being blocked
                        m_txActive = false;
                        watchdogTimer.stop();
                        LogMessage("Data from %10.10s at %10.10s blocked", incomingSrc, incomingTag); // Original log
                        // Clear new TX state members as well
                        ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH); ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
                        ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH); // Was incomingDstText before this variable was renamed
                        m_currentRptObject = nullptr; m_currentNumericDGID = 0;
                    } else {
                        LogMessage("Data from %10.10s at %10.10s blocked", incomingSrc, incomingTag); // Original log
                    }
                    continue;
                }

                uint8_t packet_numeric_dgid = buffer[39]; // DG-ID from YSF Voice Header
                bool isEOT = (buffer[34U] & 0x01U) == 0x01U; // End of Transmission flag

                // TX Lock Logic (Original structure preserved, new members added)
                if (!m_txActive) {
                    // watchdogTimer.start(); // Already called below for new TX
                    m_txActive = true;
                    ::memcpy(m_currentTag, incomingTag, YSF_CALLSIGN_LENGTH);
                    ::memcpy(m_currentSrc, incomingSrc, YSF_CALLSIGN_LENGTH);
                    ::memcpy(m_currentDst, incomingDstText, YSF_CALLSIGN_LENGTH); // Use renamed incomingDstText
                    ::memcpy(&m_currentAddr, &addr, addrLen); // Use actual addrLen
                    m_currentAddrLen = addrLen;
                    // NEW members for feature
                    m_currentRptObject = rpt;
                    m_currentNumericDGID = packet_numeric_dgid;
                    watchdogTimer.start(); // Start watchdog for new transmission
                    LogMessage("Transmission from %.10s at %.10s to TG %.10s", m_currentSrc, m_currentTag, m_currentDst); // Original log
                } else { // TX is already active
                    bool isSameTag = (::memcmp(incomingTag, m_currentTag, YSF_CALLSIGN_LENGTH) == 0);
                    bool isSameRepeater = CUDPSocket::match(addr, m_currentAddr);
                    // Additionally, ensure it's from the same repeater object that initiated the TX
                    if (!isSameTag || !isSameRepeater || m_currentRptObject != rpt) {
                        LogMessage("Ignoring overlapping TX from %.10s", incomingSrc); // Original log
                        continue;
                    }
                    watchdogTimer.start(); // Reset watchdog for ongoing transmission
                    if (::memcmp(m_currentSrc, "??????????", YSF_CALLSIGN_LENGTH) == 0) ::memcpy(m_currentSrc, incomingSrc, YSF_CALLSIGN_LENGTH);
                    if (::memcmp(m_currentDst, "??????????", YSF_CALLSIGN_LENGTH) == 0) ::memcpy(m_currentDst, incomingDstText, YSF_CALLSIGN_LENGTH);
                }

                // Forward data to other repeaters (Feature integration here)
                unsigned char forward_buffer[200U]; // Max YSF packet size is smaller, but 200U is safe
                ::memcpy(forward_buffer, buffer, len);

                if (m_currentRptObject != nullptr && m_currentRptObject->m_isInPrivateMode) {
                    forward_buffer[39] = PRIVATE_ROOM_DGID; // Modify numeric DG-ID for private mode
                } // Else, DG-ID in forward_buffer is already the original m_currentNumericDGID

                for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
                    CYSFRepeater* dest_repeater = *it;
                    // Do not send back to the originator (m_currentRptObject)
                    if (m_currentRptObject != nullptr && dest_repeater == m_currentRptObject) {
                        continue;
                    }
                    // Original code compared (*it)->m_addr with addr from network.readData.
                    // For TX lock, we use m_currentAddr. So, to not send to self, use m_currentAddr.
                    // Or better, compare dest_repeater with m_currentRptObject directly.

                    bool send_to_this_destination = false;
                    if (m_currentRptObject != nullptr) { // Ensure current transmitter is known
                        if (m_currentRptObject->m_isInPrivateMode) { // If transmitter is in private mode
                            if (dest_repeater->m_isInPrivateMode) { // Send only to other private mode users
                                send_to_this_destination = true;
                            }
                        } else { // If transmitter is in public mode
                            if (!dest_repeater->m_isInPrivateMode) { // Send only to other public mode users
                                send_to_this_destination = true;
                            }
                        }
                    }

                    if (send_to_this_destination) {
                        network.writeData(forward_buffer, len, dest_repeater->m_addr, dest_repeater->m_addrLen);
                    }
                }

                // End-of-TX detection (Original structure, with feature logic added)
                if (isEOT) { // Check EOT flag from buffer[34]
                    // Only process EOT if it's from the currently active transmitter
                    if (m_txActive && m_currentRptObject == rpt) {
                        LogMessage("Received end of transmission from %.10s at %.10s to TG %.10s", m_currentSrc, m_currentTag, m_currentDst); // Original log

                        // --- PTT Sequence Logic for the transmitting user (m_currentRptObject) ---
                        if (!m_currentRptObject->m_pttSequenceTimer.isRunning() || m_currentRptObject->m_pttSequenceTimer.hasExpired()) {
                            m_currentRptObject->m_pttPressCount = 1;
                            m_currentRptObject->m_pttSequenceTimer.start(); // Start the sequence window timer
                            // LogMessage("PTT #1 for sequence by %.10s.", m_currentSrc); // Minimal new log
                        } else {
                            m_currentRptObject->m_pttPressCount++;
                            m_currentRptObject->m_pttSequenceTimer.start(); // Reset/restart the window timer
                            // LogMessage("PTT #%d for sequence by %.10s.", m_currentRptObject->m_pttPressCount, m_currentSrc); // Minimal new log

                            if (m_currentRptObject->m_pttPressCount >= PTT_SEQUENCE_COUNT_TARGET) {
                                m_currentRptObject->m_isInPrivateMode = !m_currentRptObject->m_isInPrivateMode;
                                // Minimal new log for mode change
                                char callsign_str[YSF_CALLSIGN_LENGTH + 1];
                                ::memcpy(callsign_str, m_currentSrc, YSF_CALLSIGN_LENGTH);
                                callsign_str[YSF_CALLSIGN_LENGTH] = '\0';
                                std::string s_call(callsign_str);
                                s_call.erase(s_call.find_last_not_of(' ') + 1);

                                LogMessage("User %s %s private mode via PTT sequence.",
                                           s_call.c_str(),
                                           (m_currentRptObject->m_isInPrivateMode ? "activated" : "deactivated"));
                                m_currentRptObject->m_pttPressCount = 0;
                                m_currentRptObject->m_pttSequenceTimer.stop();
                            }
                        }
                        // --- End PTT Sequence Logic ---

                        m_txActive = false;
                        watchdogTimer.stop();
                        ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH);
                        ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
                        ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH);
                        // NEW: Clear new TX state members
                        m_currentRptObject = nullptr;
                        m_currentNumericDGID = 0;
                    }
                }
            } // End YSFD
		} // End len > 0U

		unsigned int ms = stopWatch.elapsed(); stopWatch.start();

		pollTimer.clock(ms);
		if (pollTimer.hasExpired()) {
			for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
				network.writePoll((*it)->m_addr, (*it)->m_addrLen);
			pollTimer.start();
		}

		// Remove any repeaters that haven't reported for a while (Original loop structure)
        // AND Clock PTT Sequence Timers
		for (std::vector<CYSFRepeater*>::iterator it_rpt = m_repeaters.begin(); it_rpt != m_repeaters.end(); /* manual increment */) {
            CYSFRepeater* rpt_ctx = *it_rpt;
			rpt_ctx->m_timer.clock(ms); // Existing keep-alive timer

            // --- NEW: Clock PTT sequence timer for this repeater ---
            if (rpt_ctx->m_pttSequenceTimer.isRunning()) {
                rpt_ctx->m_pttSequenceTimer.clock(ms);
                if (rpt_ctx->m_pttSequenceTimer.hasExpired()) {
                    if (rpt_ctx->m_pttPressCount > 0) { // Log only if a sequence was in progress
                        char callsign_str[YSF_CALLSIGN_LENGTH + 1];
                        ::memcpy(callsign_str, rpt_ctx->m_callsign.c_str(), YSF_CALLSIGN_LENGTH); // Use repeater callsign
                        callsign_str[YSF_CALLSIGN_LENGTH] = '\0';
                        std::string s_call(callsign_str);
                        s_call.erase(s_call.find_last_not_of(' ') + 1);
                        LogMessage("PTT sequence for %s timed out (count: %d).", s_call.c_str(), rpt_ctx->m_pttPressCount);
                    }
                    rpt_ctx->m_pttPressCount = 0;
                    rpt_ctx->m_pttSequenceTimer.stop();
                }
            }
            // --- End PTT sequence timer clocking ---

			if (rpt_ctx->m_timer.hasExpired()) { // Repeater disappeared
				char buff[80U]; // Original log buffer
				LogMessage("Removing %s (%s) disappeared", rpt_ctx->m_callsign.c_str(), CUDPSocket::display(rpt_ctx->m_addr, buff, 80U));

                if (m_txActive && m_currentRptObject == rpt_ctx) {
                    // If the disappearing repeater was the current transmitter, clear TX state.
                    // Log for this already handled by watchdog or EOT usually.
                    m_txActive = false;
                    watchdogTimer.stop();
                    ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH); ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
                    ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH);
                    m_currentRptObject = nullptr; m_currentNumericDGID = 0;
                }
                // Also reset its PTT sequence state if it disappears
                rpt_ctx->m_pttPressCount = 0;
                rpt_ctx->m_pttSequenceTimer.stop();

				delete rpt_ctx;
				it_rpt = m_repeaters.erase(it_rpt);
				network.setCount(m_repeaters.size());
			} else {
				++it_rpt;
			}
		}


		watchdogTimer.clock(ms);
		if (watchdogTimer.isRunning() && watchdogTimer.hasExpired()) {
            if (m_txActive) {
                LogMessage("Network watchdog has expired from %.10s at %.10s to TG %.10s", m_currentSrc, m_currentTag, m_currentDst); // Original log
                m_txActive = false;
                // NEW: Reset PTT sequence for the user whose TX timed out
                if (m_currentRptObject != nullptr) {
                    m_currentRptObject->m_pttPressCount = 0;
                    m_currentRptObject->m_pttSequenceTimer.stop();
                }
                ::memset(m_currentTag, 0, YSF_CALLSIGN_LENGTH); ::memset(m_currentSrc, 0, YSF_CALLSIGN_LENGTH);
                ::memset(m_currentDst, 0, YSF_CALLSIGN_LENGTH);
                // NEW: Clear new TX state members
                m_currentRptObject = nullptr;
                m_currentNumericDGID = 0;
            }
            watchdogTimer.stop();
        }

		dumpTimer.clock(ms);
		if (dumpTimer.hasExpired()) {
			dumpRepeaters();
			dumpTimer.start();
		}

		blockList.clock(ms);

		if (ms < 5U)
			CThread::sleep(5U);
	}

	network.close();

	::LogFinalise();
}

CYSFRepeater* CYSFReflector::findRepeater(const sockaddr_storage& addr) const
{
	for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		if (CUDPSocket::match(addr, (*it)->m_addr))
			return *it;
	}

	return NULL;
}

void CYSFReflector::dumpRepeaters() const
{
	if (m_repeaters.size() == 0U) {
		LogMessage("No repeaters linked on TG 226");
		return;
	}

	LogMessage("Currently linked repeaters on TG 226:");

	for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		char buffer[80U];
		LogMessage("    %s: %s %u/%u", (*it)->m_callsign.c_str(),
									   CUDPSocket::display((*it)->m_addr, buffer, 80U),
									   (*it)->m_timer.getTimer(),
									   (*it)->m_timer.getTimeout());
	}
}
