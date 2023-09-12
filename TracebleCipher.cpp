class TraceCipherText {
private:
    vector<double> trueValue;
    Ciphertext<DCRTPoly> ct;
    CryptoContext<DCRTPoly> cc;
    PrivateKey<DCRTPoly> pk;
    double errorStandard = 100000;
public:
    TraceCipherText(vector<double> tv, Ciphertext<DCRTPoly> a, CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> pk)
        : trueValue(tv), ct(a), cc(cc), pk(pk) {
        //cout << "암호문 생성" << endl;
    }

    void showDetatil() {
        cout << "scale : " << log2(ct->GetScalingFactor()) << endl;
        cout << "Level : " << ct->GetLevel() << endl;
        cout << "true value   : (";
        for (auto iter : trueValue) {
            cout << iter << ", ";
        }
        cout << ")" << endl;
        cout << "decode value : ";
        show_decode();
        errorCheck();
        cout << endl;
    }

    Ciphertext<DCRTPoly> getCiphertext() {
        return ct;
    }
    vector<double> getTrueValue() {
        return trueValue;
    }

    void setError(double error) {
        errorStandard = error;
    }

    void show_decode() {
        Plaintext plaintext;
        cc->Decrypt(pk, ct, &plaintext);
        plaintext->SetLength(8);
        cout << plaintext;
    }

    Plaintext decode() {
        Plaintext plaintext;
        cc->Decrypt(pk, ct, &plaintext);
        plaintext->SetLength(8);
        return plaintext;
    }
    void errorCheck() {
        for (int i = 0; i < trueValue.size(); i++) {
            if ((double)decode()->GetRealPackedValue()[i] >= errorStandard) { // 기준 에러보다 큼
                cout << "WARNING ! 기준 에러 " << errorStandard << " 보다 큽니다." << endl;
                cout << "index : " << i << endl;
                cout << "value : " << (double)decode()->GetRealPackedValue()[i] << endl;
                cout << endl;
            }
        }
    }
    void replace_add(TraceCipherText traceciphertext) {
        ct = cc->EvalAdd(ct, traceciphertext.getCiphertext());
        for (int i = 0; i < trueValue.size(); i++) {
            trueValue[i] += traceciphertext.getTrueValue()[i];
        }
        showDetatil();
    }

    void replace_add(double number) {
        ct = cc->EvalAdd(ct, number);
        for (int i = 0; i < trueValue.size(); i++) {
            trueValue[i] += number;
        }
        showDetatil();
    }

    void replace_Mul(TraceCipherText traceciphertext) {
        ct = cc->EvalMult(ct, traceciphertext.getCiphertext());
        for (int i = 0; i < trueValue.size(); i++) {
            trueValue[i] *= traceciphertext.getTrueValue()[i];
        }
        showDetatil();
    }

    TraceCipherText add(double number) {
        Ciphertext<DCRTPoly> newciphertext = cc->EvalAdd(ct, number);
        vector<double> newVector(trueValue.size(), 0);

        for (int i = 0; i < trueValue.size(); i++) {
            newVector[i] = trueValue[i] + number;
        }
        return TraceCipherText(newVector, newciphertext, cc, pk);
    }

    TraceCipherText add(TraceCipherText traceciphertext) {
        Ciphertext<DCRTPoly> newciphertext = cc->EvalAdd(ct, traceciphertext.getCiphertext());

        vector<double> newVector(trueValue.size(), 0);

        for (int i = 0; i < trueValue.size(); i++) {
            newVector[i] += traceciphertext.getTrueValue()[i];
        }
        //showDetatil();
        return TraceCipherText(newVector, newciphertext, cc, pk);
    }

    TraceCipherText Mul(TraceCipherText traceciphertext) {
        Ciphertext<DCRTPoly> newciphertext = cc->EvalMult(ct, traceciphertext.getCiphertext());

        vector<double> newVector(trueValue.size(), 0);

        for (int i = 0; i < trueValue.size(); i++) {
            newVector[i] = trueValue[i] * traceciphertext.getTrueValue()[i];
        }
        //showDetatil();
        return TraceCipherText(newVector, newciphertext, cc, pk);
    }

    void Rescale() {
        this->ct = cc->Rescale(ct);
    }

};