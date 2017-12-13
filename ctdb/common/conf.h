/*
   Configuration file handling on top of tini

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_CONF_H__
#define __CTDB_CONF_H__

#include <stdio.h>
#include <stdbool.h>
#include <talloc.h>

/**
 * @file conf.h
 *
 * @brief Configuration file handling with sections and key-value pairs
 *
 * CTDB settings can be written in a configuration file ctdb.conf (similar to
 * samba's smb.conf).  Various daemons and tools will consult the configuration
 * file for runtime settings.
 *
 * The configuration will be organized in sections depending on various
 * components. Each section will have various configuration options in the form
 * of key-value pairs.
 *
 * [section1]
 *	key1 = value1
 *	...
 *
 * [section2]
 *	key2 = value2
 *	...
 *
 * ...
 *
 */

/**
 * @brief Abstract data structure holding the configuration options
 */
struct conf_context;

/**
 * @brief configuration option update mode
 *
 * When a value of configuration option is changed, update mode is set
 * appropriately.
 *
 * CONF_MODE_API - value modified using set functions
 * CONF_MODE_LOAD - value modified via conf_load
 * CONF_MODE_RELOAD - value modified via conf_reload
 */
enum conf_update_mode {
	CONF_MODE_API,
	CONF_MODE_LOAD,
	CONF_MODE_RELOAD,
};

/**
 * @brief configuration option type
 */
enum conf_type {
	CONF_STRING,
	CONF_INTEGER,
	CONF_BOOLEAN,
};

/**
 * @brief Configuration section validation function
 *
 * Check if all the configuration options are consistent with each-other
 */
typedef bool (*conf_validate_section_fn)(struct conf_context *conf,
					 const char *section,
					 enum conf_update_mode mode);

/**
 * @brief Configuration option validation function for string
 *
 * Check if a configuration option value is valid
 */
typedef bool (*conf_validate_string_option_fn)(const char *key,
					       const char *old_value,
					       const char *new_value,
					       enum conf_update_mode mode);

/**
 * @brief Configuration option validation function for integer
 *
 * Check if a configuration option value is valid
 */
typedef bool (*conf_validate_integer_option_fn)(const char *key,
						int old_value,
						int new_value,
						enum conf_update_mode mode);

/**
 * @brief Configuration option validation function for boolean
 *
 * Check if a configuration option value is valid
 */
typedef bool (*conf_validate_boolean_option_fn)(const char *key,
						bool old_value,
						bool new_value,
						enum conf_update_mode mode);

/**
 * @brief Initialize configuration option database
 *
 * This return a new configuration options context.  Freeing this context will
 * free up all the memory associated with the configuration options.
 *
 * @param[in] mem_ctx  Talloc memory context
 * @param[in] result  The new configuration options context
 * @return 0 on success, errno on failure
 */
int conf_init(TALLOC_CTX *mem_ctx, struct conf_context **result);

/**
 * @brief Define a section for organizing configuration options
 *
 * This functions creates a section to organize configuration option.  The
 * section names are case-insensitive and are always stored in lower case.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] validate  The validation function for configuration options
 */
void conf_define_section(struct conf_context *conf,
			 const char *section,
			 conf_validate_section_fn validate);

/**
 * @brief Define a configuration option which has a string value
 *
 * This functions adds a new configuration option organized under a given
 * section.  Configuration options are case-insensitive and are always stored
 * in lower case.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] default_value  The default value for the configuration option
 * @param[in] validate  The validation function for the configuration option
 */
void conf_define_string(struct conf_context *conf,
			const char *section,
			const char *key,
			const char *default_value,
			conf_validate_string_option_fn validate);

/**
 * @brief Define a configuration option which has an integer value
 *
 * This functions adds a new configuration option organized under a given
 * section.  Configuration options are case-insensitive and are always stored
 * in lower case.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] default_value  The default value for the configuration option
 * @param[in] validate  The validation function for the configuration option
 */
void conf_define_integer(struct conf_context *conf,
			 const char *section,
			 const char *key,
			 const int default_value,
			 conf_validate_integer_option_fn validate);

/**
 * @brief Define a configuration option which has an boolean value
 *
 * This functions adds a new configuration option organized under a given
 * section.  Configuration options are case-insensitive and are always stored
 * in lower case.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] default_value  The default value for the configuration option
 * @param[in] validate  The validation function for the configuration option
 */
void conf_define_boolean(struct conf_context *conf,
			 const char *section,
			 const char *key,
			 const bool default_value,
			 conf_validate_boolean_option_fn validate);

/**
 * @brief Assign user-accessible pointer for string option
 *
 * This pointer can be used for accessing the value of configuration option
 * directly without requiring a function call.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] ptr  User-accessible pointer to the value
 */
void conf_assign_string_pointer(struct conf_context *conf,
				const char *section,
				const char *key,
				const char **ptr);

/**
 * @brief Assign user-accessible pointer for integer option
 *
 * This pointer can be used for accessing the value of configuration option
 * directly without requiring a function call.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] ptr  User-accessible pointer to the value
 */
void conf_assign_integer_pointer(struct conf_context *conf,
				 const char *section,
				 const char *key,
				 int *ptr);

/**
 * @brief Assign user-accessible pointer for boolean option
 *
 * This pointer can be used for accessing the value of configuration option
 * directly without requiring a function call.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[in] ptr  User-accessible pointer to the value
 * @return true on success, false on failure
 */
void conf_assign_boolean_pointer(struct conf_context *conf,
				 const char *section,
				 const char *key,
				 bool *ptr);

/**
 * @brief Query a configuration option
 *
 * This function checks if a configuration option is defined or not.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of the section
 * @param[in] key  The name of the configuration option
 * @param[out] type  The type of the configuration option
 * @return true on success, false if section/option is not defined
 */
bool conf_query(struct conf_context *conf,
		const char *section,
		const char *key,
		enum conf_type *type);

/**
 * @brief Check if the defined configuration options are valid
 *
 * This function must be called after creating configuration options
 * to confirm that all the option definitions are valid.
 *
 * @param[in] conf  The configuration options context
 * @return true on success, false on failure
 */
bool conf_valid(struct conf_context *conf);

/**
 * @brief Set the default values for all configuration options
 *
 * This function resets all the configuration options to their default values.
 *
 * @param[in] conf  The connfiguration options context
 */
void conf_set_defaults(struct conf_context *conf);

/**
 * @brief Load the values for configuration option values from a file
 *
 * This function will update the values of the configuration options from those
 * specified in a file.  This function will fail in case it encounters an
 * undefined option.  Any sections which are not defined, will be ignored.
 *
 * This function will call validation function (if specified) before updating
 * the value of a configuration option.  After updating all the values for a
 * section, the validation for section (if specified) will be called.  If any
 * of the validation functions return error, then all the configuration
 * options will be reset to their previous values.
 *
 * @param[in] conf  The configuration options context
 * @param[in] filename  The configuration file
 * @param[in] skip_unknown  Whether unknown config options should be ignored
 * @return 0 on success, errno on failure
 */
int conf_load(struct conf_context *conf,
	      const char *filename,
	      bool ignore_unknown);

/**
 * @brief Reload the values for configuration options
 *
 * This function will re-load the values of the configuration options.  This
 * function can be called only after succesful call to conf_load().
 *
 * @see conf_load
 *
 * @param[in] conf  The configuration options context
 * @return 0 on success, errno on failure.
 */
int conf_reload(struct conf_context *conf);

/**
 * @brief Set the string value of a configuration option
 *
 * This function can be used to update the value of a configuration option.
 * This will call the validation function for that option (if defined) and
 * the section validation function (if defined).
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option should not be changed via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[in] str_val  The string value
 * @return 0 on success, errno in case of failure
 */
int conf_set_string(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    const char *str_val);

/**
 * @brief Set the integer value of a configuration option
 *
 * This function can be used to update the value of a configuration option.
 * This will call the validation function for that option (if defined) and
 * the section validation function (if defined).
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option should not be changed via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[in] int_val  The integer value
 * @return 0 on success, errno in case of failure
 */
int conf_set_integer(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     int int_val);

/**
 * @brief Set the boolean value of a configuration option
 *
 * This function can be used to update the value of a configuration option.
 * This will call the validation function for that option (if defined) and
 * the section validation function (if defined).
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option should not be changed via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[in] bool_val  The boolean value
 * @return 0 on success, errno in case of failure
 */
int conf_set_boolean(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     bool bool_val);

/**
 * @brief Get the string value of a configuration option
 *
 * This function can be used to fetch the current value of a configuration
 * option.
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option can be accessed directly via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[out] str_val  The string value of the configuration option
 * @param[out] is_default  True if the value is default value
 * @return 0 on success, errno in case of failure
 */
int conf_get_string(struct conf_context *conf,
		    const char *section,
		    const char *key,
		    const char **str_val,
		    bool *is_default);

/**
 * @brief Get the integer value of a configuration option
 *
 * This function can be used to fetch the current value of a configuration
 * option.
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option can be accessed directly via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[out] int_val  The integer value of the configuration option
 * @param[out] is_default  True if the value is default value
 * @return 0 on success, errno in case of failure
 */
int conf_get_integer(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     int *int_val,
		     bool *is_default);

/**
 * @brief Get the boolean value of a configuration option
 *
 * This function can be used to fetch the current value of a configuration
 * option.
 *
 * If a user-defined storage pointer is provided, then the value of a
 * configuration option can be accessed directly via that pointer.
 *
 * @param[in] conf  The configuration options context
 * @param[in] section  The name of a section
 * @param[in] key  The name of a configuration option
 * @param[out] bool_val  The boolean value of the configuration option
 * @param[out] is_default  True if the value is default value
 * @return 0 on success, errno in case of failure
 */
int conf_get_boolean(struct conf_context *conf,
		     const char *section,
		     const char *key,
		     bool *bool_val,
		     bool *is_default);

/**
 * @brief Dump the configuration in a file
 *
 * All the configuration options are dumped with their current values.
 * If an option has a default value, then it is commented.
 *
 * Here is a sample output:
 *
 * [section1]
 *	key1 = value1
 *	key2 = value2
 *	# key3 = default_value3
 * [section2]
 *	key4 = value4
 *
 * @param[in] conf  The configuration options context
 * @param[in] fp  File pointer
 */
void conf_dump(struct conf_context *conf, FILE *fp);

#endif /* __CTDB_CONF_H__ */
