Embedded JavaScript System Model


- Need args, arg types and exceptions thrown
- Error classes

class Global
	class System
		class environment
			var 
		class GC 
			void function run()
			function tune()
			function getUsedMemory()			// Should be properties
			function getAllocatedMemory()		// Should be properties

		var javascript
		var null
		var undefined
		var true
		var false
		var Nan
		var Infinity

		function random								// Not implemented
		function sleep								// Not implemented
		function exit
		function yield								// Not implemented

		Debug
			isDebugMode

		Limits
			isLimitsMode					// Not implemented
			stack							// Not implemented
			heap							// Not implemented
			flash							// Not implemented

		Memory
			getUsedMemory()					// Should be properties
			getAvailableMemory()			// Should be properties
			used
			flash							// Not implemented

	assert()
	breakpoint()
	dirname()
	basename()
	eval()
	exit()
	print()
	println()
	printVars()
	sleep()
	sort()
	time()
	typeof()
	include()
	trace()
	printf()								// Not implemented
	sprintf()

	
