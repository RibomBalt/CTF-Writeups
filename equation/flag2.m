%% 1. check significance
% flag2_fake = 'flag{g00d_1inear_equationxz}';
% pmat = get_pmat(28);
% output_fake = pmat * double(flag2_fake)';
% output_fake_str = arrayfun(@(f)sprintf('%.15g', f), output_fake, 'UniformOutput',false);
fake_res = {'16219.6205804627', '16379.4929803494', '16616.9161887669', '16757.7516464342', '16966.0638368890', '17350.6779080683', '17061.0665872390', '16766.0710924715', '16461.7079468599', '16154.7477451663', '15856.6320486005', '15573.2223382852', '15269.2898799001', '14981.1583242866', '14681.5311021234', '14292.8333577865', '14339.5476221573', '14393.2059773257', '14468.8647349355', '14562.3371757082', '14672.1901086943', '14773.9386077777', '14886.6317440886', '15023.2656822303', '15156.0216948338', '15328.7295597819', '15514.7322208494', '15837.7530879794'};

fake_double = cellfun(@str2double, fake_res);
pmat = get_pmat(28);
res = pmat \ fake_double';
plot(res - round(res));
res_str = char(round(res)');
disp(res_str)

%% 2. solve flag2
% len(flag) = 18 + 10, with 6 known,
raw_output = {'19106.6119577929', '19098.1846041713', '19124.6925013201', '19072.8591005901', '19063.3797914261', '19254.8741381550', '19410.9493230296', '18896.7331405884', '19021.3167024024', '18924.6509997019', '18853.3351082021', '18957.2296714145', '18926.7035797566', '18831.7182995672', '18768.8192204100', '18668.7452791590', '18645.9207293335', '18711.1447224940'};

% raw_output = fake_res(1:18);
output = cellfun(@str2double, raw_output);
pmat = get_pmat(28);

guess_index = [24 25 26 27];
solu_index = setdiff(6:27, guess_index);
[~, Isort] = sort([guess_index, solu_index]);

known_parts = double('}flag{');
known_pmat = pmat(1:18, [28 1:5]);
known_output = known_pmat * known_parts';
guess_pmat = pmat(1:18, guess_index);
solu_pmat = pmat(1:18, solu_index);
solu_guess_output = output' - known_output;

letter_freq = 'etaoinsrhlducfmwygpbvkxjqz';
guess_pool = double(['e390t7ao152ns86i4rhld_ucfmwy-gpbvkxjqz','A':'Z'])';
nguess = length(guess_pool);

% guess_vec: 
ok_result = [];
ok_norm = [];
parfor i1 = 1:nguess
    guess_vec = zeros(4,1);
    guess_pool = double(['e390t7ao152ns86i4rhld_ucfmwy-gpbvkxjqz','A':'Z'])';
    guess_vec(1) = guess_pool(i1);
    
    min_err = inf;
    for i2 = 1:nguess
        guess_vec(2) = guess_pool(i2);
        for i3 = 1:nguess
            guess_vec(3) = guess_pool(i3);
            for i4 = 1:nguess
                guess_vec(4) = guess_pool(i4);
                % solve
                guess_output = guess_pmat * guess_vec;
                solu_output = solu_guess_output - guess_output;
                res = solu_pmat \ solu_output;
                orig_err = res - round(res);
                err = (orig_err'*orig_err)/18;
%                 err_mean(i2,i3,i4) = err;
%                 disp((res'*res)/18)
                if min_err > err
                    min_err = err;
                end
                if all(res > 30) && all(res < 127) && (err < 1e-10)
                    disp(char(guess_vec)')
                    ok_result = [ok_result [guess_vec; res]];
                    ok_norm = [ok_norm sqrt(err)];
                end
            end
        end
    end
    fprintf("%d: %.3g\n", i1, min_err)
end
ok_result = ok_result(Isort, :);
flag2_str = ['flag{' char(round(ok_result)') '}'];

%% 3. get flag2
% guess_vec = double('y0u_')';
guess_vec = double('sser')';
guess_output = guess_pmat * guess_vec;
solu_output = solu_guess_output - guess_output;
res = solu_pmat \ solu_output;
char_stack = char([guess_vec; round(res)]');
flag2_str = ['flag{' char_stack(Isort) '}']
% flag{y0u_`re^a^fonc_gudrreq} fake flag?
% flag{y0u_are_a_good_guesser} real one!

%% functions
function res = get_pmat(n)
    PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271];
    primes = PRIMES(1:n);
    res = zeros(n, n);
    for ii = 1:n
        res(ii, :) = primes;
        primes = primes([n 1:(n-1)]);
    end
    res = sqrt(res);
end