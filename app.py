
import streamlit as st
import pandas as pd
import re

from ciphers import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    rail_fence_encrypt, rail_fence_decrypt,
    columnar_encrypt, columnar_decrypt,
    substitution_encrypt, substitution_decrypt,
    playfair_encrypt, playfair_decrypt,
    hill_encrypt, hill_decrypt,
)

from cryptanalysis import (
    caesar_brute_force,
    frequency_analysis,
    index_of_coincidence,
    vigenere_key_length_analysis,
    playfair_key_search,
    hill_cipher_analysis,
)


# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="Classical Cryptography Lab",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Classical Cryptography Lab")
st.caption("ECE — Number Theory and Cryptography")


# =====================================================
# SESSION STATE
# =====================================================

defaults = {
    "ciphertext": "",
    "recovered": "",
    "original_plaintext": "",
    "active_cipher": "",
    "active_key": None,
    "last_action": "",
    "enc_signature": None,
}

for name, value in defaults.items():
    if name not in st.session_state:
        st.session_state[name] = value


def clear_results():
    st.session_state["ciphertext"] = ""
    st.session_state["recovered"] = ""
    st.session_state["original_plaintext"] = ""
    st.session_state["active_cipher"] = ""
    st.session_state["active_key"] = None
    st.session_state["last_action"] = ""


# =====================================================
# SIDEBAR NAVIGATION
# =====================================================

st.sidebar.header("🔐 Cryptography Lab")

page = st.sidebar.radio(
    "Mode",
    [
        "Encryption / Decryption",
        "Cryptanalysis",
    ],
    key="main_mode",
)


# =====================================================
# CIPHER HELPER FUNCTIONS
# =====================================================

def encrypt_message(text, cipher, key):
    if cipher == "Caesar":
        return caesar_encrypt(text, int(key))

    elif cipher == "Vigenere":
        return vigenere_encrypt(text, key)

    elif cipher == "Monoalphabetic Substitution":
        return substitution_encrypt(text, key)

    elif cipher == "Playfair":
        return playfair_encrypt(text, key)

    elif cipher == "Hill (2x2)":
        return hill_encrypt(text, key)

    elif cipher == "Rail Fence":
        return rail_fence_encrypt(text, int(key))

    elif cipher == "Columnar Transposition":
        return columnar_encrypt(text, key)

    raise ValueError("Unsupported cipher selected.")


def decrypt_message(text, cipher, key):
    if cipher == "Caesar":
        return caesar_decrypt(text, int(key))

    elif cipher == "Vigenere":
        return vigenere_decrypt(text, key)

    elif cipher == "Monoalphabetic Substitution":
        return substitution_decrypt(text, key)

    elif cipher == "Playfair":
        return playfair_decrypt(text, key)

    elif cipher == "Hill (2x2)":
        return hill_decrypt(text, key)

    elif cipher == "Rail Fence":
        return rail_fence_decrypt(text, int(key))

    elif cipher == "Columnar Transposition":
        return columnar_decrypt(text, key)

    raise ValueError("Unsupported cipher selected.")


# =====================================================
# MODULE 1: ENCRYPTION / DECRYPTION
# =====================================================

if page == "Encryption / Decryption":

    st.header("🔒 Classical Cipher Encryption and Decryption")

    st.sidebar.subheader("Cipher Configuration")

    cipher = st.sidebar.selectbox(
        "Select Cipher",
        [
            "Caesar",
            "Vigenere",
            "Monoalphabetic Substitution",
            "Playfair",
            "Hill (2x2)",
            "Rail Fence",
            "Columnar Transposition",
        ],
        key="cipher_choice",
    )

    if cipher == "Caesar":
        key = st.sidebar.number_input(
            "Shift Key",
            min_value=0,
            max_value=25,
            value=3,
            step=1,
            key="caesar_key",
        )

    elif cipher == "Rail Fence":
        key = st.sidebar.number_input(
            "Number of Rails",
            min_value=2,
            value=3,
            step=1,
            key="rail_key",
        )

    elif cipher == "Vigenere":
        key = st.sidebar.text_input(
            "Encryption Keyword",
            value="LEMON",
            key="vigenere_key",
        )

    elif cipher == "Monoalphabetic Substitution":
        key = st.sidebar.text_input(
            "26-letter substitution alphabet",
            value="QWERTYUIOPASDFGHJKLZXCVBNM",
            key="substitution_key",
        )

    elif cipher == "Playfair":
        key = st.sidebar.text_input(
            "Playfair Keyword",
            value="MONARCHY",
            key="playfair_key",
        )

    elif cipher == "Hill (2x2)":
        key = st.sidebar.text_input(
            "Matrix key (a,b,c,d)",
            value="3,3,2,5",
            key="hill_key",
        )

    else:
        key = st.sidebar.text_input(
            "Columnar Keyword",
            value="ZEBRA",
            key="columnar_key",
        )

    # Clear old results only when cipher or key changes.
    signature = (cipher, str(key))

    if st.session_state["enc_signature"] != signature:
        clear_results()
        st.session_state["enc_signature"] = signature

    st.sidebar.info(
        "Choose a cipher and key, enter your message, "
        "then encrypt and decrypt using the same settings."
    )

    st.info(
        "Enter plaintext and click Encrypt. The ciphertext will "
        "remain available when you click Decrypt."
    )

    plaintext = st.text_area(
        "Enter Plaintext",
        placeholder="Type your original message here...",
        height=140,
        key="plaintext_input",
    )

    col1, col2 = st.columns(2)

    with col1:
        encrypt_clicked = st.button(
            "🔒 Encrypt",
            use_container_width=True,
            key="encrypt_button",
        )

    with col2:
        decrypt_clicked = st.button(
            "🔓 Decrypt",
            use_container_width=True,
            key="decrypt_button",
        )

    # ---------------- ENCRYPT ----------------

    if encrypt_clicked:

        if not plaintext.strip():
            st.warning("Enter a message before encrypting.")

        else:
            try:
                result = encrypt_message(plaintext, cipher, key)

                if not isinstance(result, str) or not result:
                    raise ValueError(
                        "Encryption returned an empty result."
                    )

                st.session_state["ciphertext"] = result
                st.write("DEBUG CIPHERTEXT:", repr(st.session_state["ciphertext"]))
                st.session_state["recovered"] = ""
                st.session_state["original_plaintext"] = plaintext
                st.session_state["active_cipher"] = cipher
                st.session_state["active_key"] = str(key)
                st.session_state["last_action"] = "encrypt"

            except Exception as error:
                clear_results()
                st.error(
                    f"Encryption failed: {type(error).__name__}: {error}"
                )

    # ---------------- DECRYPT ----------------

    if decrypt_clicked:

        ciphertext = st.session_state["ciphertext"]

        if not ciphertext:
            st.warning("Encrypt a message first.")

        elif (
            cipher != st.session_state["active_cipher"]
            or str(key) != st.session_state["active_key"]
        ):
            st.warning(
                "Use the same cipher and key that you used for encryption."
            )

        else:
            try:
                result = decrypt_message(ciphertext, cipher, key)

                if not isinstance(result, str) or not result:
                    raise ValueError(
                        "Decryption returned an empty result."
                    )

                st.session_state["recovered"] = result
                st.session_state["last_action"] = "decrypt"

            except Exception as error:
                st.session_state["recovered"] = ""
                st.session_state["last_action"] = ""
                st.error(
                    f"Decryption failed: {type(error).__name__}: {error}"
                )

    # ---------------- STATUS ----------------

    if st.session_state["last_action"] == "encrypt":
        st.success("Encryption completed successfully!")

    elif st.session_state["last_action"] == "decrypt":
        st.success("Decryption completed successfully!")

    
    # ---------------- RESULTS ----------------

    st.divider()
    st.subheader("📋 Results")

    # Update widget state BEFORE creating the output widgets
    st.session_state["ciphertext_display"] = st.session_state["ciphertext"]
    st.session_state["recovered_display"] = st.session_state["recovered"]

    st.text_area(
        "Ciphertext",
        height=100,
        disabled=True,
        key="ciphertext_display",
    )

    st.text_area(
        "Decrypted Plaintext",
        height=100,
        disabled=True,
        key="recovered_display",
    )

    if st.session_state["last_action"] == "decrypt":
        recovered = st.session_state["recovered"]
        original = st.session_state["original_plaintext"]

        if recovered == original:
            st.success("Decryption successful! Original message recovered.")
        else:
            st.warning(f"Decryption completed. Recovered text: {recovered}")



# =====================================================
# MODULE 2: CRYPTANALYSIS
# =====================================================

elif page == "Cryptanalysis":

    st.header("🕵️ Cryptanalysis Tools")
    st.write(
        "Analyze ciphertext using brute force, letter frequencies, "
        "and the Index of Coincidence."
    )

    analysis_tool = st.sidebar.selectbox(
        "Select Analysis Tool",
        [
            "Caesar Brute Force",
            "Frequency Analysis",
            "Index of Coincidence",
            "Vigenère Key-Length Analysis",
            "Playfair Key-Search Attack",
            "Hill-Cipher Analysis",
        ],
        key="analysis_tool",
    )

    st.sidebar.info(
        "These tools analyze text independently of the encryption module."
    )

    # -------------------------------------------------
    # CAESAR BRUTE FORCE
    # -------------------------------------------------

    if analysis_tool == "Caesar Brute Force":

        st.subheader("🔓 Caesar Cipher Brute-Force Attack")

        st.write(
            "Try all 26 shifts to identify a possible plaintext."
        )

        ciphertext = st.text_area(
            "Enter Caesar Ciphertext",
            placeholder="Example: KHOOR ZRUOG",
            height=130,
            key="brute_force_input",
        )

        if st.button(
            "Run Brute Force",
            use_container_width=True,
            key="brute_force_button",
        ):

            if not ciphertext.strip():
                st.warning("Enter ciphertext first.")

            else:
                try:
                    results = caesar_brute_force(ciphertext)

                    if results:
                        st.dataframe(
                            pd.DataFrame(results),
                            use_container_width=True,
                            hide_index=True,
                        )
                        st.caption(
                            "Inspect the candidate plaintexts to identify "
                            "the likely shift."
                        )
                    else:
                        st.warning("No candidate results were returned.")

                except Exception as error:
                    st.error(
                        f"Analysis failed: {type(error).__name__}: {error}"
                    )

    # -------------------------------------------------
    # FREQUENCY ANALYSIS
    # -------------------------------------------------

    elif analysis_tool == "Frequency Analysis":

        st.subheader("📊 Letter Frequency Analysis")

        st.write(
            "Count alphabetic characters and calculate their "
            "percentage in the input text."
        )

        text = st.text_area(
            "Enter Plaintext or Ciphertext",
            placeholder="Enter text to analyze...",
            height=140,
            key="frequency_input",
        )

        if st.button(
            "Analyze Frequencies",
            use_container_width=True,
            key="frequency_button",
        ):

            if not text.strip():
                st.warning("Enter text to analyze.")

            else:
                try:
                    results = frequency_analysis(text)
                    dataframe = pd.DataFrame(results)

                    if (
                        dataframe.empty
                        or "count" not in dataframe.columns
                        or dataframe["count"].sum() == 0
                    ):
                        st.warning(
                            "Enter at least one English alphabetic character."
                        )

                    else:
                        col1, col2 = st.columns(2)

                        with col1:
                            st.subheader("Frequency Table")
                            st.dataframe(
                                dataframe,
                                use_container_width=True,
                                hide_index=True,
                            )

                        with col2:
                            st.subheader("Letter Frequency Chart")
                            if "letter" in dataframe.columns:
                                chart_data = dataframe.set_index(
                                    "letter"
                                )[["count"]]
                                st.bar_chart(chart_data)

                except Exception as error:
                    st.error(
                        f"Analysis failed: {type(error).__name__}: {error}" 
                    )

    # -------------------------------------------------
    # INDEX OF COINCIDENCE
    # -------------------------------------------------

    elif analysis_tool == "Index of Coincidence":

        st.subheader("🔬 Index of Coincidence (IC)")

        st.write(
            "The IC measures the likelihood that two randomly chosen "
            "letters from a text are identical. It can help compare "
            "patterns in classical ciphertexts."
        )

        text = st.text_area(
            "Enter Plaintext or Ciphertext",
            placeholder="Enter alphabetic text...",
            height=140,
            key="ic_input",
        )

        if st.button(
            "Calculate IC",
            use_container_width=True,
            key="ic_button",
        ):

            alphabetic_count = sum(
                1
                for char in text
                if char.isascii() and char.isalpha()
            )

            if alphabetic_count < 2:
                st.warning(
                    "Enter at least two alphabetic characters."
                )

            else:
                try:
                    ic_value = index_of_coincidence(text)

                    st.metric(
                        "Index of Coincidence",
                        f"{ic_value:.6f}",
                    )

                    st.caption(
                        f"Alphabetic characters analyzed: {alphabetic_count}"
                    )

                    if ic_value > 0.06:
                        st.info(
                            "The IC is relatively high. This can be "
                            "consistent with natural-language text or "
                            "some monoalphabetic ciphers. IC alone "
                            "cannot identify a cipher."
                        )

                    else:
                        st.info(
                            "The IC is relatively low. This can occur "
                            "with some polyalphabetic ciphertexts. "
                            "IC alone cannot identify a cipher."
                        )

                except Exception as error:
                    st.error(
                        f"Analysis failed: {type(error).__name__}: {error}"
                    )


    # -------------------------------------------------
    # VIGENERE KEY-LENGTH ANALYSIS
    # -------------------------------------------------

    elif analysis_tool == "Vigenère Key-Length Analysis":

        st.subheader("🔑 Vigenère Key-Length Analysis")

        st.write(
            "Estimate possible Vigenère key lengths using the "
            "average Index of Coincidence (IC). Higher values "
            "may indicate more promising candidate lengths."
        )

        ciphertext = st.text_area(
            "Enter Vigenère Ciphertext",
            placeholder="Paste a sufficiently long ciphertext...",
            height=140,
            key="vigenere_length_input",
        )

        max_length = st.slider(
            "Maximum key length to test",
            min_value=2,
            max_value=30,
            value=16,
            key="vigenere_max_length",
        )

        if st.button(
            "Analyze Key Length",
            use_container_width=True,
            key="vigenere_length_button",
        ):

            if len([
                char for char in ciphertext
                if char.isascii() and char.isalpha()
            ]) < 4:
                st.warning(
                    "Enter a longer ciphertext containing "
                    "at least four English letters."
                )

            else:
                try:
                    results = vigenere_key_length_analysis(
                        ciphertext,
                        max_key_length=max_length,
                    )

                    if results:
                        dataframe = pd.DataFrame(results)

                        st.subheader("Candidate Key Lengths")

                        st.dataframe(
                            dataframe,
                            use_container_width=True,
                            hide_index=True,
                        )

                        chart_data = dataframe.set_index(
                            "key_length"
                        )[["average_ic"]]

                        st.subheader("Average IC by Key Length")
                        st.bar_chart(chart_data)

                        st.caption(
                            "These are candidate lengths, not a "
                            "guaranteed key-length recovery. Short "
                            "ciphertexts may produce unreliable rankings."
                        )

                    else:
                        st.warning(
                            "Unable to estimate key lengths from this input."
                        )

                except Exception as error:
                    st.error(
                        f"Analysis failed: {type(error).__name__}: {error}"
                    )

    # -------------------------------------------------
    # PLAYFAIR KEY-SEARCH ATTACK
    # -------------------------------------------------

    elif analysis_tool == "Playfair Key-Search Attack":

        st.subheader("🔐 Playfair Key-Search Attack")

        st.write(
            "Test candidate keywords against a Playfair ciphertext "
            "and rank the resulting plaintexts."
        )

        ciphertext = st.text_area(
            "Enter Playfair Ciphertext",
            placeholder="Enter ciphertext...",
            height=120,
            key="playfair_attack_ciphertext",
        )

        candidate_text = st.text_area(
            "Candidate Keywords (one per line or comma-separated)",
            placeholder="MONARCHY\nKEYWORD\nEXAMPLE",
            height=120,
            key="playfair_candidate_keys",
        )

        if st.button(
            "Search Candidate Keys",
            use_container_width=True,
            key="playfair_attack_button",
        ):
            if not ciphertext.strip():
                st.warning("Enter Playfair ciphertext first.")

            elif not candidate_text.strip():
                st.warning("Enter at least one candidate keyword.")

            else:
                candidate_keys = [
                    key.strip()
                    for key in re.split(r"[\n,]+", candidate_text)
                    if key.strip()
                ]

                try:
                    results = playfair_key_search(
                        ciphertext,
                        candidate_keys,
                    )

                    if results:
                        st.subheader("Ranked Candidate Keys")
                        st.dataframe(
                            pd.DataFrame(results),
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.warning("No candidate keys were tested.")

                except Exception as error:
                    st.error(
                        f"Attack failed: {type(error).__name__}: {error}"
                    )

    
    # -------------------------------------------------
    # HILL CIPHER ANALYSIS
    # -------------------------------------------------

    elif analysis_tool == "Hill-Cipher Analysis":

        st.subheader("🔢 Hill-Cipher Known-Plaintext Analysis")

        st.write(
            "Recover a 2x2 Hill cipher key using matching "
            "plaintext and ciphertext."
        )

        plaintext = st.text_area(
            "Known Plaintext",
            placeholder="Example: HELP",
            key="hill_analysis_plaintext",
        )

        ciphertext = st.text_area(
            "Matching Ciphertext",
            placeholder="Enter the corresponding ciphertext...",
            key="hill_analysis_ciphertext",
        )

        if st.button(
            "Recover Hill Key",
            use_container_width=True,
            key="hill_analysis_button",
        ):

            if not plaintext.strip() or not ciphertext.strip():
                st.warning(
                    "Enter both plaintext and matching ciphertext."
                )

            else:
                try:
                    result = hill_cipher_analysis(
                        plaintext,
                        ciphertext,
                    )

                    if result["success"]:
                        st.success(result["message"])

                        st.subheader("Recovered Key Matrix")

                        st.table(
                            pd.DataFrame(
                                result["key_matrix"],
                                index=["Row 1", "Row 2"],
                                columns=["Column 1", "Column 2"],
                            )
                        )

                        st.write(
                            "**Key as letters:**",
                            " / ".join(result["key_letters"]),
                        )

                        st.caption(
                            "The key was checked against all supplied "
                            "plaintext/ciphertext blocks."
                        )

                    else:
                        st.warning(result["message"])

                except Exception as error:
                    st.error(
                        f"Analysis failed: {type(error).__name__}: {error}"
                    )
 
# =====================================================
# FOOTER
# =====================================================

st.divider()

st.caption(
    "Educational demonstration only. Classical ciphers are not "
    "suitable for modern data security."
)
