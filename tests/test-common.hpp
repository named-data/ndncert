/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2019, Regents of the University of California,
 *                          Arizona Board of Regents,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University,
 *                          Washington University in St. Louis,
 *                          Beijing Institute of Technology,
 *                          The University of Memphis.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#ifndef NDNCERT_TESTS_TEST_COMMON_HPP
#define NDNCERT_TESTS_TEST_COMMON_HPP

#include "boost-test.hpp"
#include <boost/asio/io_service.hpp>
#include <ndn-cxx/util/time-unit-test-clock.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

/** \brief a test fixture that overrides steady clock and system clock
 */
class UnitTestTimeFixture
{
public:
  UnitTestTimeFixture()
    : steadyClock(make_shared<time::UnitTestSteadyClock>())
    , systemClock(make_shared<time::UnitTestSystemClock>())
  {
    time::setCustomClocks(steadyClock, systemClock);
  }

  ~UnitTestTimeFixture()
  {
    time::setCustomClocks(nullptr, nullptr);
  }

  /** \brief advance steady and system clocks
   *
   *  Clocks are advanced in increments of \p tick for \p nTicks ticks.
   *  After each tick, io_service is polled to process pending I/O events.
   *
   *  Exceptions thrown during I/O events are propagated to the caller.
   *  Clock advancing would stop in case of an exception.
   */
  void
  advanceClocks(const time::nanoseconds& tick, size_t nTicks = 1)
  {
    this->advanceClocks(tick, tick * nTicks);
  }

  /** \brief advance steady and system clocks
   *
   *  Clocks are advanced in increments of \p tick for \p total time.
   *  The last increment might be shorter than \p tick.
   *  After each tick, io_service is polled to process pending I/O events.
   *
   *  Exceptions thrown during I/O events are propagated to the caller.
   *  Clock advancing would stop in case of an exception.
   */
  void
  advanceClocks(const time::nanoseconds& tick, const time::nanoseconds& total)
  {
    BOOST_ASSERT(tick > time::nanoseconds::zero());
    BOOST_ASSERT(total >= time::nanoseconds::zero());

    time::nanoseconds remaining = total;
    while (remaining > time::nanoseconds::zero()) {
      if (remaining >= tick) {
        steadyClock->advance(tick);
        systemClock->advance(tick);
        remaining -= tick;
      }
      else {
        steadyClock->advance(remaining);
        systemClock->advance(remaining);
        remaining = time::nanoseconds::zero();
      }

      if (m_io.stopped())
        m_io.reset();
      m_io.poll();
    }
  }

public:
  shared_ptr<time::UnitTestSteadyClock> steadyClock;
  shared_ptr<time::UnitTestSystemClock> systemClock;
  boost::asio::io_service m_io;
};

} // namespace tests
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_TESTS_TEST_COMMON_HPP
