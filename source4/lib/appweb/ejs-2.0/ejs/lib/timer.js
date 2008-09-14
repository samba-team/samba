/*
 *	@file 	timer.js
 *	@brief 	Timer class
 *	@copy 	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 *
 *	Usage:
 *		timer = new System.Timer("name", period);
 *		timer.onTick = function(arg) {
 *			//	Anything here
 *		}
 *		timer.start();
 *	or
 *
 *		timer = new System.Timer("name", period, obj, method);
 *		timer.start();
 */

/******************************************************************************/

class System.Timer
{
	var		id;

	/* MOB -- really need accessor on period. If user updates period, 
		then due must be updated. */
	var		period;
	var		due;
	var		runOnce;					// Run timer just once
	var		method;						// Callback method
	var		obj;						// Callback object 

	function Timer(id, period, obj, method)
	{
		this.id = id;
		this.period = period;
		due = time() + period;

		if (arguments.length >= 3) {
			this.obj = obj;
		} else {
			this.obj = this;
		}
		if (arguments.length >= 4) {
			this.method = method;
		} else {
			this.method = "onTick";
		}
	}
	
	/* MOB this should be deprecated */
	function reschedule(period)
	{
		/* MOB -- should update the timer service somehow */
		this.period = period;
	}

	function run(now)
	{
		if (obj[method] == undefined) {
			trace("Timer cant find timer method " + method);
			due = now + this.period;
			return;
		}

		/*
		 *	Run the timer
		 */
		try {
			obj[method](this);
		}
		catch (error) {
			trace("Timer exception: " + error);
		}

		if (runOnce) {
			timerService.removeTimer(this);

		} else {
			due = now + this.period;
		}
	}

	function start()
	{
		if (obj[method] == undefined) {
			throw new Error("Callback method is undefined");
		} else {
			timerService.addTimer(this);
		}
	}

	function stop()
	{
		timerService.removeTimer(this);
	}

}

/* MOB -- should not need this */
Timer = System.Timer;


/* 
 *	Timer service
 */
class System.TimerService
{
	var		timers;
	var		nextDue;

	function TimerService() 
	{
		timers = new Object();
		nextDue = 0;
		global.timerService = this;
	}

	function addTimer(timer)
	{
		timers[timer.id] = timer;
	}

	function removeTimer(timer)
	{
		try {
			delete timers[timer.id];
		}
		catch {}
	}

	function getIdleTime()
	{
		return nextDue - time();
	}

	function runTimers()
	{
		var		now = time();

		nextDue = 2147483647; 		/* MOB -- MATH.MAX_INT; */

		for each (var timer in timers)
		{
			if (timer.due < now) {
				timer.run(now);
			}
		}
		for each (var timer in timers)
		{
			if (timer.due < nextDue) {
				nextDue = timer.due;
			}
		}
		// println("runTimers leaving with " + (nextDue - now));
		return nextDue - time();
	}
}
TimerService = System.TimerService;
