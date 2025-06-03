/*
*   Copyright (C) 2016,2020 by Jonathan Naylor G4KLX
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

#if !defined(YSFReflector_H)
#define	YSFReflector_H

#include "YSFDefines.h" // For YSF_CALLSIGN_LENGTH
#include "Timer.h"      // For CTimer
#include "Conf.h"       // For CConf

#include <cstdio>
#include <string>
#include <vector>
#include <cstdint> // For uint8_t

#if !defined(_WIN32) && !defined(_WIN64)
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <WS2tcpip.h> // For sockaddr_storage etc. on Windows
#endif

// Define constants for PTT sequence feature
// These are used by CYSFRepeater constructor and logic in YSFReflector.cpp
const uint8_t PRIVATE_ROOM_DGID = 99;    // DG-ID for private room communications
const int PTT_SEQUENCE_COUNT_TARGET = 3; // Number of PTTs to trigger mode switch
const unsigned int PTT_SEQUENCE_WINDOW_SECONDS = 5; // Window for PTT sequence (in seconds)


class CYSFRepeater {
public:
	CYSFRepeater() :
	    m_callsign(),
	    // m_addr and m_addrLen are set when repeater is added
	    m_timer(1000U, 60U), // Keep-alive timer: 1s tick, 60s timeout
        // Initialize new members for private mode and PTT sequence
        m_isInPrivateMode(false),
        m_pttPressCount(0),
        m_pttSequenceTimer(1000U, PTT_SEQUENCE_WINDOW_SECONDS) // PTT sequence timer
	{
        m_timer.stop(); // Ensure timer is not running until first poll/activity
        m_pttSequenceTimer.stop(); // Ensure PTT sequence timer is not running initially
	}

	std::string      m_callsign;
	sockaddr_storage m_addr;
	unsigned int     m_addrLen;
	CTimer           m_timer;           // Keep-alive timer

    // New members for private mode and PTT sequence feature
    bool             m_isInPrivateMode;   // True if user is in private mode
    uint8_t          m_pttPressCount;     // Counter for PTT sequence
    CTimer           m_pttSequenceTimer;  // Timer for the PTT sequence window
};

class CYSFReflector
{
public:
	CYSFReflector(const std::string& file);
	~CYSFReflector();

	void run();

private:
    CConf                      m_conf;
    std::vector<CYSFRepeater*> m_repeaters;

    // Member variables for current transmission state
    bool                       m_txActive;
    unsigned char              m_currentTag[YSF_CALLSIGN_LENGTH];    // Callsign of current transmitting hotspot/repeater
    unsigned char              m_currentSrc[YSF_CALLSIGN_LENGTH];    // Callsign of current transmitting user
    unsigned char              m_currentDst[YSF_CALLSIGN_LENGTH];    // Textual destination from current packet (TG name/callsign)
    sockaddr_storage           m_currentAddr;                        // Network address of current transmitter
    unsigned int               m_currentAddrLen;                     // Length of current transmitter address

    // New members for tracking current transmitter object and its numeric DG-ID
    CYSFRepeater*              m_currentRptObject;   // Pointer to the CYSFRepeater object of the current transmitter
    uint8_t                    m_currentNumericDGID; // Numeric DG-ID of the current transmission stream

    // Private member functions
    CYSFRepeater* findRepeater(const sockaddr_storage& addr) const;
    void dumpRepeaters() const;
};

#endif
