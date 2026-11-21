import time

from colorama import Fore

from utility.get_time import get_time

class Logger:

    def custom_input(query: str):

        """
        Print a success message to the console.
        """

        user_input = input(Fore.MAGENTA + f"[ {get_time()} ] " + Fore.CYAN + f"[ : ] {query}")
        return user_input

    def print_success(message: str):

        """
        Print a success message to the console.
        """

        print(Fore.MAGENTA + f"[ {get_time()} ] " + Fore.GREEN + f"[ + ] {message}")
        return

    def print_info(message: str):

        """
        Print an information message to the console.
        """

        print(Fore.MAGENTA + f"[ {get_time()} ] " + Fore.WHITE + f"[ / ] {message}")
        return

    def print_warning(message: str):

        """
        Print a warning message to the console.
        """

        print(Fore.MAGENTA + f"[ {get_time()} ] " + Fore.YELLOW + f"[ ! ] {message}")
        return

    def print_error(message: str):

        """
        Print an error message to the console.
        """

        print(Fore.MAGENTA + f"[ {get_time()} ] " + Fore.RED + f"[ - ] {message}")
        return